cmd_Release/obj.target/multihashing/scryptn.o := cc '-D_DARWIN_USE_64_BIT_INODE=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/Users/ahmedbodi/.node-gyp/0.10.33/src -I/Users/ahmedbodi/.node-gyp/0.10.33/deps/uv/include -I/Users/ahmedbodi/.node-gyp/0.10.33/deps/v8/include -I../crypto  -Os -gdwarf-2 -mmacosx-version-min=10.5 -arch x86_64 -Wall -Wendif-labels -W -Wno-unused-parameter -fno-strict-aliasing -MMD -MF ./Release/.deps/Release/obj.target/multihashing/scryptn.o.d.raw  -c -o Release/obj.target/multihashing/scryptn.o ../scryptn.c
Release/obj.target/multihashing/scryptn.o: ../scryptn.c ../scryptn.h \
  ../sha256.h
../scryptn.c:
../scryptn.h:
../sha256.h:
