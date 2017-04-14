package org.sanchez.sergio.hadoop_examples.hdfs;


import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

public final class HdfsReader extends Configured implements Tool {
	
	public static final String FS_PARAM_NAME = "fs.defaultFS";

	public int run(String[] args) throws Exception {
		
		int exitCode = 0;
		
		if (args.length == 2) { 
			Path inputPath = new Path(args[0]);
			String localOutputPath = args[1];
	        Configuration conf = getConf();
	        System.out.println("configured filesystem = " + conf.get(FS_PARAM_NAME));
	        FileSystem fs = FileSystem.get(conf);
	        InputStream is = fs.open(inputPath);
	        OutputStream os = new BufferedOutputStream(new FileOutputStream(localOutputPath));
	        IOUtils.copyBytes(is, os, conf);
		} else {
			System.err.println("HdfsReader [hdfs input path] [local output path]");
			exitCode = 1;
		}
		
		return exitCode;  
	}
	
	public static void main(String[] args) throws Exception {
		int returnCode = ToolRunner.run(new HdfsReader(), args);
        System.exit(returnCode);
	}

}
