# TheN00bBuilder: 1/11/2025
# extract_minifs.py
# BRIEF: extracts minifs contents from TPLink VxWorks firmware

import lzma
from os import makedirs, path
import argparse
ENDIANNESS = "big"
SET_FILEPATH = ""

# BRIEF: helper to convert byte array to integer of selected endianness
# PARAM: byte_array - byte array to convert
def bytearray_to_int(byte_array):
    return int.from_bytes(byte_array, ENDIANNESS)

# thanks to https://stackoverflow.com/questions/37400583/python-lzma-compressed-data-ended-before-the-end-of-stream-marker-was-reached
def decompress_lzma(data):
    results = []
    while True:
        decomp = lzma.LZMADecompressor(lzma.FORMAT_AUTO, None, None)
        try:
            res = decomp.decompress(data)
        except LZMAError:
            if results:
                break  # Leftover data is not a valid LZMA/XZ stream; ignore it.
            else:
                raise  # Error on the first iteration; bail out.
        results.append(res)
        data = decomp.unused_data
        if not data:
            break
        if not decomp.eof:
            raise LZMAError("Compressed data ended before the end-of-stream marker was reached")
    return b"".join(results)

# BRIEF: get length of nametable for safety
# PARAM: nametable - bytes of the nametable
def nametable_len(nametable):
    filename_count = 0
    # iterate over each char
    for char in nametable:
        char = char.to_bytes(1, "big")
        # count number of NUL bytes
        if (char == b'\x00'):
            filename_count += 1
    return filename_count

# BRIEF: decompress and calculate LZMA chunk
# PARAM: position - chunk index in chunk table
# PARAM: chunktable - bytes of the chunktable
# PARAM: start_of_chunks - where first LZMA header exists
# PARAM: minifs_bytes - bytes of file, for extraction work
def get_chunk(position, chunktable, start_of_chunks, minifs_bytes):
    # get position of chunk in table
    chunk_position = position * 12
    '''
    FORMAT 12b:
    4b: offset to the start of the LZMA chunk
    4b: size of the compressed LZMA chunk
    4b: size of the decompressed LZMA chunk
    '''
    offset = bytearray_to_int(chunktable[chunk_position:chunk_position+4])
    size = bytearray_to_int(chunktable[chunk_position+4:chunk_position+8])
    decomp_sz = bytearray_to_int(chunktable[chunk_position+8:chunk_position+12])
    # extract chunk from filebytes
    lzma_chunk = minifs_bytes[start_of_chunks + offset:start_of_chunks + offset + size]
    # perform decompression
    decomp_bytes = decompress_lzma(lzma_chunk)
    if (len(decomp_bytes) != decomp_sz):
        print("[!] ERROR: Chunk actual size (", len(decomp_bytes), ") doesn't match predicted (", decomp_sz, ")")
    return decomp_bytes

# BRIEF: do extraction work for all files
# PARAM: file_count - count of files to extract (typically the number of strings in the nametable)
# PARAM: nametable - bytes of the nametable
# PARAM: chunktable - bytes of the chunktable
# PARAM: end_chunk_table - where the end of the chunk table is - next byte begins the chunks themselves
# PARAM: minifs_bytes - file bytes
def perform_extraction(file_count, nametable, filetable, chunktable, end_chunk_table, minifs_bytes):
    # so now we have everything, steps are...
    #   0. iterate over file table
    #   1. get name table offset for path
    #   2. get name table offset for filename
    #   3. find chunk
    #   4. extract chunk
    #   5. write bytes and verify file size
    global SET_FILEPATH
    file_bytes = b""
    for i in range(0, file_count * 20, 20):
        # i: index of the entry in the filetable
        '''
        FORMAT 20b:
        4b: bytes to path in name table
        4b: bytes to filename in name table
        4b: chunk number to extract
        4b: where the file starts in the chunk
        4b: file size in chunk
        '''
        pathint = bytearray_to_int(filetable[i:i+4])
        filename = bytearray_to_int(filetable[i+4:i+8])
        chunk_num = bytearray_to_int(filetable[i+8:i+12])
        chunk_off = bytearray_to_int(filetable[i+12:i+16])
        filesz = bytearray_to_int(filetable[i+16:i+20])
        # get decompressed chunk
        chunk_bytes = get_chunk(chunk_num, chunktable, end_chunk_table, minifs_bytes)
        file_bytes = chunk_bytes[chunk_off:chunk_off+filesz] 
        # get the path, by finding pos of NUL and decoding it for mkdir
        # we're pretty much doing a strcopy() here
        file_path = nametable[pathint:]
        path_end = file_path.find(b'\x00')
        file_path = nametable[pathint:pathint+path_end].decode("utf-8")
        # get the filename, same as we did above
        filename_str = nametable[filename:]
        filename_end = filename_str.find(b'\x00')
        filename_str = nametable[filename:filename+filename_end].decode("utf-8")
        # make dir if not already made
        try:
            makedirs(path.join(SET_FILEPATH, file_path))
        except FileExistsError as e:
            pass
        # write file
        filename_str = path.join(SET_FILEPATH,file_path,filename_str)
        f = open(filename_str, 'wb+')
        f.write(file_bytes)
        print("[+] Wrote ", filename_str)
        f.close()
    return

# BRIEF: preprocess the file to point it to the magic bytes
# PARAM: file_bytes - file bytes to parse through
def get_minifs_bytes(file_bytes):
    # find where the header starts
    pos = file_bytes.find(b'MINIFS')
    # in case it's pos 0, check both cases before returning a bad array
    if (pos == 0 and file_bytes[0:6] != b"MINIFS"):
        return b""
    else:
        return file_bytes[pos:]


def main():
    global SET_FILEPATH
    global ENDIANNESS

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='Path to your firmware file containing the MINIFS magic', required=True)
    parser.add_argument('-o', '--output', help='Path to the output directory. If it is not made, it will be.', required=True)
    parser.add_argument('-e', '--endian', help='Specify endianness for integers, typically same as the processor', nargs='?', default="big")
    args = parser.parse_args()
    ENDIANNESS = args.endian
    SET_FILEPATH = args.output
    inputfile = args.input

    f = open(inputfile, 'rb')
    minifs_bytes = get_minifs_bytes(f.read())
    f.close()
    if (minifs_bytes == b''):
        print("[!] ERROR: no MINIFS magic in file!")
        exit(1)
    # check file count
    file_count = bytearray_to_int(minifs_bytes[20:24])
    name_table_len = bytearray_to_int(minifs_bytes[28:32])
    '''      FORMAT
    ==== Lower Memory ====
    Header      |
    Name Table  |
    File Table  |
    Chunk Table |
    LZMA Files  |
    ....        V
    ==== Higher Memory ====
    '''
    print("[+] File count: ", bytearray_to_int(minifs_bytes[20:24]))
    print("[+] Name table size: ", bytearray_to_int(minifs_bytes[28:32]))
    nametable = minifs_bytes[0x20:name_table_len+0x20]
    nt_len = nametable_len(nametable)
    if (nt_len != file_count):
        print("[!] NOTE: Header file count", file_count, "doesn't match calculated string table size ", nt_len)
        print("[!] Extraction will continue, but make sure the files are what they say they are in the name.")
    # now lets get the file tables
    filetable = minifs_bytes[name_table_len+0x20:name_table_len+0x20+file_count*20]
    # and finally, chunk table
    # each entry is 20b for the filetable
    begin_chunk_table = name_table_len+0x20 + file_count*20
    # 0x5d000080 - LZMA header, find the 1st one
    end_chunk_table = minifs_bytes.find(b"\x5d\x00\x00\x80")
    chunktable = minifs_bytes[begin_chunk_table:end_chunk_table]
    # perform extraction now
    perform_extraction(file_count, nametable, filetable, chunktable, end_chunk_table, minifs_bytes)
    print("[+] Extraction completed.")

if __name__ == "__main__":
    main()
