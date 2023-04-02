package unit;

import unit.crypto.*;
import haxe.ds.List;
import unit.Test.*;
import utest.Runner;
import utest.ui.Report;

final asyncWaits = new Array<haxe.PosInfos>();
final asyncCache = new Array<() -> Void>();

@:access(unit.Test)
#if js
@:expose("unit.TestMain.main")
@:keep
#end

function main() {
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

	var verbose = #if (cpp || neko || php) Sys.args().indexOf("-v") >= 0 #else false #end;

	#if cs // "Turkey Test" - Issue #996
	cs.system.threading.Thread.CurrentThread.CurrentCulture = new cs.system.globalization.CultureInfo('tr-TR');
	cs.Lib.applyCultureChanges();
	#end
	#if neko
	if (neko.Web.isModNeko)
		neko.Web.setHeader("Content-Type", "text/plain");
	#elseif php
	if (php.Web.isModNeko)
		php.Web.setHeader("Content-Type", "text/plain");
	#end
	#if !macro
	trace("Generated at: " + HelperMacros.getCompilationDate());
	#end
	trace("START");
	#if flash
	var tf:flash.text.TextField = untyped flash.Boot.getTrace();
	tf.selectable = true;
	tf.mouseEnabled = true;
	#end	
	var classes = [
		new AesTest(),
		#if (!flash)
		new BlowFishTest(),
		new ModeTest(),
		new PaddingTest(),
		new TripleDesTest(),
		new Sha224Test(),
		new Sha256Test(),
		new HmacTest(),
		new TwoFishTest(),
		new Ripemd160Test(),
		new BCryptTest(),
		new Pbkdf2Test(),
		new Sha384Test(),
		new Sha512Test(),
		new Salsa20Test(),
		new XSalsa20Test(),
		new ChaChaTest(),
		new RC4Test(),
		new XChaCha20Test(),
		#end
		#if (!win32 && !flash)
		new SCryptTest(),
		#end
		#if (!neko && !flash)
		// neko bug https://github.com/HaxeFoundation/haxe/issues/10806
		new Poly1305Test()
		#end
	];	
	TestIssues.addIssueClasses("src/unit/issues", "unit.issues");
	
	var runner = new Runner();
	for (c in classes) {
		runner.addCase(c);
	}
	var report = Report.create(runner);
	report.displayHeader = AlwaysShowHeader;
	report.displaySuccessResults = NeverShowSuccessResults;
	var success = true;
	runner.onProgress.add(function(e) {
		for (a in e.result.assertations) {
			switch a {
				case Success(pos):
				case Warning(msg):
				case Ignore(reason):
				case _:
					success = false;
			}
		}
		#if js
		if (js.Browser.supported && e.totals == e.done) {
			untyped js.Browser.window.success = success;
		};
		#end
	});
	#if sys
	if (verbose)
		runner.onTestStart.add(function(test) {
			Sys.println(' $test...'); // TODO: need utest success state for this
		});
	#end
	runner.run();
}
