package runci.targets;

import runci.System.*;
import runci.Config.*;

class Jvm {
	static public function run(args:Array<String>) {
		deleteDirectoryRecursively("bin/jvm");
		Java.getJavaDependencies();

		for (level in 0...3) {
			final args = args.concat(["-D", "jvm.dynamic-level=" + level]);
			runCommand("haxe", ["compile-jvm.hxml"].concat(args));
			runCommand("java", ["-jar", "bin/unit.jar"]);

			runCommand("haxe", ["compile-jvm.hxml", "-dce", "no"].concat(args));
			runCommand("java", ["-jar", "bin/unit.jar"]);
		}
	}
}
