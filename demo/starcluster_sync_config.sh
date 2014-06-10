#!/bin/bash
starcluster get strongbox_cluster --node master /root/strongbox_owner_config.pickle strongbox_owner_config.pickle
starcluster put strongbox_cluster --node node001 strongbox_owner_config.pickle /root
rm strongbox_owner_config.pickle

starcluster get strongbox_cluster --node master /root/strongbox_backup_config.pickle strongbox_backup_config.pickle
starcluster put strongbox_cluster --node node002 strongbox_backup_config.pickle /root
rm strongbox_backup_config.pickle
