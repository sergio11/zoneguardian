## oozie sqoop action

For the execution of the workflow, it is necessary to follow the following steps:

### Hive setup tasks

1. Create SysLogEvents table.

``
CREATE EXTERNAL TABLE SysLogEvents(
month_name STRING,
day STRING,
time STRING,
host STRING,
event STRING,
log STRING)
PARTITIONED BY(node string,year int, month int)
ROW FORMAT SERDE 'org.apache.hadoop.hive.contrib.serde2.RegexSerDe' 
WITH SERDEPROPERTIES (
"input.regex" = "(\\w+)\\s+(\\d+)\\s+(\\d+:\\d+:\\d+)\\s+(\\w+\\W*\\w*)\\s+(.*?\\:)\\s+(.*$)"
)
``
    
2. We split the table to improve the time of the queries.

``
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dev01",year=2013, month=04)
location '/user/oozieProject/data/airawat-syslog/cdh-dev01/2013/04/';

Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dev01",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-dev01/2013/05/';
 
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dn01",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-dn01/2013/05/';
 
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dn02",year=2013, month=04)
location '/user/oozieProject/data/airawat-syslog/cdh-dn02/2013/04/';

Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dn02",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-dn02/2013/05/';
 
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dn03",year=2013, month=04)
location '/user/oozieProject/data/airawat-syslog/cdh-dn03/2013/04/';

Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-dn03",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-dn03/2013/05/';
 
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-jt01",year=2013, month=04)
location '/user/oozieProject/data/airawat-syslog/cdh-jt01/2013/04/';

Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-jt01",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-jt01/2013/05/';
 
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-nn01",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-nn01/2013/05/';
 
Alter table SysLogEvents Add IF NOT EXISTS partition(node="cdh-vms",year=2013, month=05)
location '/user/oozieProject/data/airawat-syslog/cdh-vms/2013/05/';
``

3. Create and populates the source table for the sqoop action

``
CREATE TABLE IF NOT EXISTS eventsgranularreport(
year int,
month int,
day int,
event STRING,
occurrence int)
ROW FORMAT DELIMITED 
FIELDS TERMINATED by ','
LINES TERMINATED by '\n';
``

``
INSERT OVERWRITE TABLE eventsgranularreport
select Year,Month,Day,Event,Count(*) Occurrence from SysLogEvents group by year,month,day,event order by event asc,year,month,day desc;
``
## Oozie commands

1. Submit job

``oozie job -oozie http://sergio-desktop:11000/oozie -config /home/sergio/git/hadoop_samples/hadoop_examples/src/main/java/org/sanchez/sergio/hadoop_examples/oozie/workflowSqoopAction/job.properties -submit``

`` job: 0000000-170414210219841-oozie-serg-W ``

2. Run job.

`` oozie job -oozie http://sergio-desktop:11000/oozie -start 0000000-170414210219841-oozie-serg-W ``






