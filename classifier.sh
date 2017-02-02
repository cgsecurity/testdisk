## pvaldes 2017-01-27
## This script examine the content of each file recovered by photorec and will put it in a directory 
## with other files of the same type, making much easier to find what we are looking for. 
## It the dir does not exist will be created automatically in the current working directory.

## i.e. All Phyton scripts in recup_dirXXX will be automatically moved to a new dir named Python/, 
## all makefiles to makefile/ all chunks of C++ files to C++, etc... 

for i in `find . -type f`; do
     tipo=`file $i | awk '{gsub("/","-"); print $2}'`

     if [ ! -d "../$tipo" ]
     then
	 mkdir "../$tipo"
     fi
     mv -i $i ../$tipo/
     tipo=""
done

exit 0
