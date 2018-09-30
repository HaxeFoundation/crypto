package runci.targets;

import sys.FileSystem;
import runci.System.*;
import runci.Config.*;
using StringTools;

class Java {
	static public function getJavaDependencies() {
		haxelibInstallGit("HaxeFoundation", "hxjava", true);
		runCommand("javac", ["-version"]);
	}

	static public function run(args:Array<String>) {
		getJavaDependencies();
		runCommand("haxe", ["compile-java.hxml"].concat(args));
		runCommand("java", ["-jar", "bin/java/TestMain-Debug.jar"]);

		runCommand("haxe", ["compile-java.hxml","-dce","no"].concat(args));
		runCommand("java", ["-jar", "bin/java/TestMain-Debug.jar"]);
	}
}