package unit;

import unit.crypto.*;
import haxe.ds.List;
import unit.Test.*;

@:access(unit.Test)
@:expose("unit.TestMain")
@:keep
class TestMain {

	static var asyncWaits = new Array<haxe.PosInfos>();
	static var asyncCache = new Array<Void -> Void>();

	#if js
	static function nodejsMain() {
		main();
		(untyped process).exit(Test.success ? 0 : 1);
	}
	#end

	static function main() {
		Test.startStamp = haxe.Timer.stamp();

		#if js
		if (js.Browser.supported) {
			var oTrace = haxe.Log.trace;
			var traceElement = js.Browser.document.getElementById("haxe:trace");
			haxe.Log.trace = function(v, ?infos) {
				oTrace(v, infos);
				traceElement.innerHTML += infos.fileName + ":" + infos.lineNumber + ": " + StringTools.htmlEscape(v) + "<br/>";
			}
		}
		#end

		var verbose = #if ( cpp || neko || php ) Sys.args().indexOf("-v") >= 0 #else false #end;

		#if neko
		if( neko.Web.isModNeko )
			neko.Web.setHeader("Content-Type","text/plain");
		#elseif php
		if( php.Web.isModNeko )
			php.Web.setHeader("Content-Type","text/plain");
		#end
		resetTimer();
		#if !macro
		trace("Generated at: " + HelperMacros.getCompilationDate());
		#end
		trace("START");
		#if flash
		var tf : flash.text.TextField = untyped flash.Boot.getTrace();
		tf.selectable = true;
		tf.mouseEnabled = true;
		#end
		var classes = [
			new AesTest(),
			new BlowFishTest(),
			new ModeTest(),
			new PaddingTest(),
			new TripleDesTest()
		];

		TestIssues.addIssueClasses("src/unit/issues", "unit.issues");
		var current = null;
		#if (!fail_eager)
		try
		#end
		{
			asyncWaits.push(null);
			for( inst in classes ) {
				current = Type.getClass(inst);
			if (verbose)
			   logVerbose("Class " + Std.string(current) );
				for( f in Type.getInstanceFields(current) )
					if( f.substr(0,4) == "test" ) {
				  if (verbose)
					 logVerbose("   " + f);
						#if fail_eager
						Reflect.callMethod(inst,Reflect.field(inst,f),[]);
						#else
						try {
							Reflect.callMethod(inst,Reflect.field(inst,f),[]);
						}
						#if !as3
						catch( e : Dynamic ) {
							onError(e,"EXCEPTION",Type.getClassName(current)+"."+f);
						}
						#end
						#end
						reportInfos = null;
					}
			}
			asyncWaits.remove(null);
			checkDone();
		}
		#if (!as3 && !(fail_eager))
		catch( e : Dynamic ) {
			asyncWaits.remove(null);
			onError(e,"ABORTED",Type.getClassName(current));
		}
		#end
	}
}