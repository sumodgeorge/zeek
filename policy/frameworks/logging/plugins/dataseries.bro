##! Interface for the dataseries log writer.

module LogDataSeries;

export {
    ## Compression to use with the DS output file.  Options are:
	## 'none' -- No compression.
	## 'lzf' -- LZF compression.  Very quick, but leads to larger output files
	## 'lzo' -- LZO compression.  Very fast decompression times
	## 'gz' -- GZIP compression.  Slower than LZF, but also produces smaller output
	## 'bz2' -- BZIP2 compression.  Slower than GZIP, but also produces smaller output
	const ds_compression = "lzf" &redef;

    ## Extent buffer size.
	## TODO: Tweak this value.
	const ds_extent_size = 65536 &redef;

	## Should we dump the XML schema we use for this ds file to disk?
	## If yes, the XML schema shares the name of the logfile, but has
	## an XML ending.
	const ds_dump_schema = T &redef;

	## How many threads should DataSeries spawn to perform compression?
	## Note that this dictates the number of threads per log stream.  If
	## you're using a lot of streams, you may want to keep this number
	## relatively small.
	##
	## Default value is 0, which will spawn one thread / core / stream
	## 
	## MAX is 128, MIN is 1
	const ds_num_threads = 1 &redef;
}

