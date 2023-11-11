package runci.targets;

import sys.FileSystem;
import haxe.io.Path;
import runci.System.*;
import runci.Config.*;

using StringTools;

class Java {
	static final miscJavaDir = getMiscSubDir('java');

	static public function getJavaDependencies() {
		haxelibInstallGit("HaxeFoundation", "hxjava", true);
		runCommand("javac", ["-version"]);
	}

	static public function run(args:Array<String>) {
		deleteDirectoryRecursively("bin/java");
		getJavaDependencies();

		runCommand("haxe", ["compile-java.hxml"].concat(args));
		runCommand("java", ["-jar", "bin/java/TestMain-Debug.jar"]);

		runCommand("haxe", ["compile-java.hxml", "-dce", "no"].concat(args));
		runCommand("java", ["-jar", "bin/java/TestMain-Debug.jar"]);
	}
}
