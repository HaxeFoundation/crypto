package runci.targets;

import sys.FileSystem;
import runci.System.*;
import runci.Config.*;

class Cpp {
	static public var gotCppDependencies = false;
	static final miscCppDir = getMiscSubDir('cpp');

	static public function getCppDependencies() {
		if (gotCppDependencies) return;

		//hxcpp dependencies
		switch (systemName) {
			case "Linux":
				Linux.requireAptPackages(["gcc-multilib", switch Linux.arch {
					case Arm64: "g++-multilib-arm-linux-gnueabi";
					case Amd64: "g++-multilib";
				}]);
			case "Mac":
				//pass
		}


		//install and build hxcpp
		try {
			final path = getHaxelibPath("hxcpp");
			infoMsg('hxcpp has already been installed in $path.');
		} catch(e:Dynamic) {
			haxelibInstallGit("HaxeFoundation", "hxcpp", true);
			final oldDir = Sys.getCwd();
			changeDirectory(getHaxelibPath("hxcpp") + "tools/hxcpp/");
			runCommand("haxe", ["-D", "source-header=''", "compile.hxml"]);
			changeDirectory(oldDir);
		}

		gotCppDependencies = true;
	}

	static public function runCpp(bin:String, ?args:Array<String>):Void {
		if (args == null) args = [];
		bin = FileSystem.fullPath(bin);
		runCommand(bin, args);
	}

	static public function run(args:Array<String>, testCompiled:Bool, testCppia:Bool) {
		getCppDependencies();

		final isLinuxArm64 = systemName == 'Linux' && Linux.arch == Arm64;

		final archFlag = switch systemName {
			case 'Windows':
				'HXCPP_M32';
			case 'Linux' if(Linux.arch == Arm64):
				'HXCPP_LINUX_ARM64';
			case _:
				'HXCPP_M64';
		}

		if (testCompiled) {
			runCommand("rm", ["-rf", "cpp"]);
			runCommand("haxe", ["compile-cpp.hxml", "-D", archFlag].concat(args));
			runCpp("bin/cpp/TestMain-debug", []);
		}

		if (testCppia) {
			runCommand("haxe", ["compile-cppia-host.hxml", "-D", archFlag].concat(args));
			runCommand("haxe", ["compile-cppia.hxml"].concat(args));
			runCpp("src/unit/bin/cppia/Host-debug", ["bin/unit.cppia"]);

			if (!isLinuxArm64) // FIXME
				runCpp("src/unit/bin/cppia/Host-debug", ["bin/unit.cppia", "-jit"]);
		}

	}
}
