Demo
======

The demo screencast was made using StarCluster (v0.95.5) to simplify managing the necessary Amazon EC2 instances.

To create a cluster for testing StrongBox, edit the `strongbox_starcluster_config` file, supplying your AWS keys, then run the command
```
starcluster -c strongbox_starcluster_config start strongbox_cluster
```

Once you're finished testing, you can shut down the cluster with the command
```
starcluster terminate strongbox_cluster
```

To verify that you won't be charged by Amazon for keeping an idle cluster up, list your running clusters with the command
```
starcluster listclusters
```

