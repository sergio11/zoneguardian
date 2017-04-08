package org.sanchez.sergio.hadoop_examples.hdfs;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

public final class HdfsWriter extends Configured implements Tool{
	
	public static final String FS_PARAM_NAME = "fs.defaultFS";

	public int run(String[] args) throws Exception {
		
		int exitCode = 0;
		if (args.length == 2) {
			String localInputPath = args[0];
	        Path outputPath = new Path(args[1]);
	        Configuration conf = getConf();
	        System.out.println("configured filesystem = " + conf.get(FS_PARAM_NAME));
	        FileSystem fs = FileSystem.get(conf);
	        if (!fs.exists(outputPath)) {
	        	OutputStream os = fs.create(outputPath);
	            InputStream is = new BufferedInputStream(new FileInputStream(localInputPath));
	            IOUtils.copyBytes(is, os, conf);
	        } else {
	        	System.err.println("output path exists");
	        	exitCode = 1;
	        }
            
        } else {
        	System.err.println("HdfsWriter [local input path] [hdfs output path]");
        	exitCode = 1;
        }
		
		return exitCode;
	}
	
	public static void main( String[] args ) throws Exception {
        int returnCode = ToolRunner.run(new HdfsWriter(), args);
        System.exit(returnCode);
    }

}
