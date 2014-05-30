#!/bin/bash

# Tested with StarCluster 0.95.5

starcluster put strongbox_cluster --node master ../StrongBox.py ../DirectoryMerkelTree.py /root
starcluster put strongbox_cluster --node node001 ../StrongBox.py ../DirectoryMerkelTree.py /root
starcluster put strongbox_cluster --node node002 ../StrongBox.py ../DirectoryMerkelTree.py /root
