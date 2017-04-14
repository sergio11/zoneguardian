## Oozie Projects


The steps required to deploy an **Oozie workflow application** in HDFS are:

1. Create a new deployment directory for the application

`` hdfs dfs -mkdir /user/oozieProject ``

2. We are located in the directory where we manage the workflow with eclipse and return its content to HDFS.

`` cd /home/sergio/git/hadoop_samples/hadoop_examples/src/main/java/org/sanchez/sergio/hadoop_examples/oozie/ ``

`` hdfs dfs -put ./* /user/oozieProject/ ``

3. We check your load, recursively listing the entire project in HDFS

`` hdfs dfs -ls -R  /user/oozieProject | awk '{ print $8 }' ``
