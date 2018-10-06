package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Pbkdf2;

class Pbkdf2Test extends Test
{

    public function test():Void
    {
        trace("Pbkdf2 started...");
        var time = Timer.stamp();

        var key = Bytes.ofString("password");
        var salt = Bytes.ofString("salt");
	    var pbkdf2 : Pbkdf2 = new Pbkdf2(SHA1);
        var data = pbkdf2.encode(key,salt,1,20);
        eq(data.toHex(),"0c60c80f961f0e71f3a9b524af6012062fe037a6");
        data = pbkdf2.encode(key,salt,2,20);
        eq(data.toHex(),"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
        data = pbkdf2.encode(key,salt,20,20);
        eq(data.toHex(),"3fa5ec8ee44d6d3fd38205716cf705ec621caab1");
        data = pbkdf2.encode(key,salt,4096,20);
        eq(data.toHex(),"4b007901b765489abead49d926f721d065a429c1");
		#if !flash
		//for flash script has executed for longer than the default timeout period of 15 seconds
        key = Bytes.ofString("passwordPASSWORDpassword");
        salt = Bytes.ofString("saltSALTsaltSALTsaltSALTsaltSALTsalt");
        data = pbkdf2.encode(key,salt,4096,25);
        eq(data.toHex(),"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
        key = Bytes.ofString("bill");
        salt = Bytes.ofString("salt");
        data = pbkdf2.encode(key,salt,4096,20);
        eq(data.toHex(),"c4ed6bab10468a29fe46fe6f16c2ac9b6ea23974");
		#end
        time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
    }

}
