package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;
import haxe.Int64;

/**
 * Argon2 - RFC 9106  (supports Argon2d, Argon2i, and Argon2id)
 */
class Argon2 {
    static inline var ARGON2_VERSION:Int = 0x13;
    static inline var BLOCK_SIZE:Int = 1024;
    static inline var QWORDS_IN_BLOCK:Int = 128;
    static inline var SYNC_POINTS:Int = 4;
    
    // Argon2 types
    public static inline var TYPE_D:Int = 0;   // Argon2d
    public static inline var TYPE_I:Int = 1;   // Argon2i
    public static inline var TYPE_ID:Int = 2;  // Argon2id

    public static function hash(password:Bytes, salt:Bytes, type:Int, timeCost:Int = 3, memoryCostKiB:Int = 65536, parallelism:Int = 4, hashLength:Int = 32, ?secret:Bytes, ?associatedData:Bytes):Bytes {
        
        if (timeCost < 1) throw "Time cost must be at least 1";
        if (parallelism < 1) throw "Parallelism must be at least 1";
        if (hashLength < 4) throw "Hash length must be at least 4";

        var memoryBlocks = Std.int(memoryCostKiB * 1024 / BLOCK_SIZE);
        if (memoryBlocks < 8 * parallelism) memoryBlocks = 8 * parallelism;

        var laneLength = Std.int(memoryBlocks / parallelism);
        laneLength = Std.int(laneLength / 4) * 4;
        memoryBlocks = laneLength * parallelism;
        var segmentLength = Std.int(laneLength / SYNC_POINTS);

        var h0 = initialHash(password, salt, timeCost, memoryCostKiB, parallelism, hashLength, type, secret, associatedData);
        
        var memory = new Vector<Vector<Int64>>(memoryBlocks);
        for (i in 0...memoryBlocks) {
            memory[i] = new Vector<Int64>(QWORDS_IN_BLOCK);
            for (j in 0...QWORDS_IN_BLOCK) memory[i][j] = Int64.ofInt(0);
        }

        for (lane in 0...parallelism) {
            var input0 = Bytes.alloc(72);
            input0.blit(0, h0, 0, 64);
            writeLE32(input0, 64, 0);
            writeLE32(input0, 68, lane);
            bytesToBlock(variableLengthHash(input0, BLOCK_SIZE), memory[lane * laneLength]);

            var input1 = Bytes.alloc(72);
            input1.blit(0, h0, 0, 64);
            writeLE32(input1, 64, 1);
            writeLE32(input1, 68, lane);
            bytesToBlock(variableLengthHash(input1, BLOCK_SIZE), memory[lane * laneLength + 1]);
        }

        for (pass in 0...timeCost) {
            for (slice in 0...SYNC_POINTS) {
                for (lane in 0...parallelism) {
                    fillSegment(memory, type, pass, lane, slice, parallelism, segmentLength, laneLength, memoryBlocks, timeCost);
                }
            }
        }

        var finalBlock = new Vector<Int64>(QWORDS_IN_BLOCK);
        for (i in 0...QWORDS_IN_BLOCK) finalBlock[i] = memory[laneLength - 1][i];
        for (lane in 1...parallelism) {
            var idx = lane * laneLength + laneLength - 1;
            for (i in 0...QWORDS_IN_BLOCK) finalBlock[i] = Int64.xor(finalBlock[i], memory[idx][i]);
        }

        return variableLengthHash(blockToBytes(finalBlock), hashLength);
    }

    static function initialHash(password:Bytes, salt:Bytes, timeCost:Int, memoryCost:Int, parallelism:Int, hashLength:Int, type:Int, ?secret:Bytes, ?ad:Bytes):Bytes {
        if (password == null) password = Bytes.alloc(0);
        if (salt == null) salt = Bytes.alloc(0);
        if (secret == null) secret = Bytes.alloc(0);
        if (ad == null) ad = Bytes.alloc(0);

        var b2 = new Blake2b(64);
        b2.update(intToBytes(parallelism));
        b2.update(intToBytes(hashLength));
        b2.update(intToBytes(memoryCost));
        b2.update(intToBytes(timeCost));
        b2.update(intToBytes(ARGON2_VERSION));
        b2.update(intToBytes(type));
        b2.update(intToBytes(password.length));
        b2.update(password);
        b2.update(intToBytes(salt.length));
        b2.update(salt);
        b2.update(intToBytes(secret.length));
        if (secret.length > 0) b2.update(secret);
        b2.update(intToBytes(ad.length));
        if (ad.length > 0) b2.update(ad);
        return b2.digest();
    }

    static function variableLengthHash(input:Bytes, outLen:Int):Bytes {
        if (outLen <= 64) {
            var b2 = new Blake2b(outLen);
            b2.update(intToBytes(outLen));
            b2.update(input);
            return b2.digest();
        }

        var output = Bytes.alloc(outLen);
        var b2 = new Blake2b(64);
        b2.update(intToBytes(outLen));
        b2.update(input);
        var outBuffer = b2.digest();

        output.blit(0, outBuffer, 0, 32);
        var outPos = 32;
        var toproduce = outLen - 32;

        while (toproduce > 64) {
            var inBuffer = Bytes.alloc(64);
            inBuffer.blit(0, outBuffer, 0, 64);
            
            var b2n = new Blake2b(64);
            b2n.update(inBuffer);
            outBuffer = b2n.digest();
            
            output.blit(outPos, outBuffer, 0, 32);
            outPos += 32;
            toproduce -= 32;
        }

        var inBuffer = Bytes.alloc(64);
        inBuffer.blit(0, outBuffer, 0, 64);
        
        var b2f = new Blake2b(toproduce);
        b2f.update(inBuffer);
        outBuffer = b2f.digest();
        
        output.blit(outPos, outBuffer, 0, toproduce);
        
        return output;
    }

    static function fillSegment(memory:Vector<Vector<Int64>>, type:Int, pass:Int, lane:Int, slice:Int, parallelism:Int, segLen:Int, laneLen:Int, memBlocks:Int, totalPasses:Int) {
        
        // Should we use data-independent addressing
        var dataIndependent = false;
        if (type == TYPE_I) {
            dataIndependent = true;
        } else if (type == TYPE_ID) {
            dataIndependent = (pass == 0 && slice < 2);
        }
        // Argon2d - dataIndependent = false
        
        var pseudoRands:Vector<Int64> = null;
        if (dataIndependent) pseudoRands = genAddressBlock(type, pass, lane, slice, memBlocks, totalPasses, segLen);

        for (idx in 0...segLen) {
            var curr = lane * laneLen + slice * segLen + idx;
            if (pass == 0 && slice == 0 && idx < 2) continue;

            var prev:Int;
            if (idx == 0 && slice == 0) prev = lane * laneLen + laneLen - 1;
            else if (idx == 0) prev = lane * laneLen + slice * segLen - 1;
            else prev = curr - 1;

            var rand:Int64 = dataIndependent ? pseudoRands[idx] : memory[prev][0];
            var j1 = rand.low;
            var j2 = rand.high;

            var refLane:Int;
            if (pass == 0 && slice == 0) refLane = lane;
            else refLane = (j2 >= 0) ? (j2 % parallelism) : (((j2 % parallelism) + parallelism) % parallelism);

            var same = (refLane == lane);
            var refArea = computeRefArea(pass, slice, idx, segLen, laneLen, same);
            var refIdx = computeRefIndex(j1, refArea, pass, slice, segLen, laneLen);
            var ref = refLane * laneLen + refIdx;

            fillBlock(memory[prev], memory[ref], memory[curr], pass != 0);
        }
    }

    static function genAddressBlock(type:Int, pass:Int, lane:Int, slice:Int, memBlocks:Int, totalPasses:Int, segLen:Int):Vector<Int64> {
        var rands = new Vector<Int64>(segLen);
        var input = new Vector<Int64>(QWORDS_IN_BLOCK);
        var zero = new Vector<Int64>(QWORDS_IN_BLOCK);
        var addr = new Vector<Int64>(QWORDS_IN_BLOCK);

        for (i in 0...QWORDS_IN_BLOCK) {
            input[i] = Int64.ofInt(0);
            zero[i] = Int64.ofInt(0);
            addr[i] = Int64.ofInt(0);
        }

        input[0] = Int64.ofInt(pass);
        input[1] = Int64.ofInt(lane);
        input[2] = Int64.ofInt(slice);
        input[3] = Int64.ofInt(memBlocks);
        input[4] = Int64.ofInt(totalPasses);
        input[5] = Int64.ofInt(type);

        for (i in 0...segLen) {
            if (i % QWORDS_IN_BLOCK == 0) {
                input[6] = Int64.ofInt(Std.int(i / QWORDS_IN_BLOCK) + 1);
                var tmp = new Vector<Int64>(QWORDS_IN_BLOCK);
                for (j in 0...QWORDS_IN_BLOCK) tmp[j] = Int64.ofInt(0);
                fillBlock(zero, input, tmp, false);
                fillBlock(zero, tmp, addr, false);
            }
            rands[i] = addr[i % QWORDS_IN_BLOCK];
        }
        return rands;
    }

    static function computeRefArea(pass:Int, slice:Int, idx:Int, segLen:Int, laneLen:Int, same:Bool):Int {
        var size:Int;
        if (pass == 0) {
            if (slice == 0) size = idx - 1;
            else size = same ? (slice * segLen + idx - 1) : (slice * segLen + (idx == 0 ? -1 : 0));
        } else {
            size = same ? (laneLen - segLen + idx - 1) : (laneLen - segLen + (idx == 0 ? -1 : 0));
        }
        return size <= 0 ? 1 : size;
    }

    static function computeRefIndex(j1:Int, refArea:Int, pass:Int, slice:Int, segLen:Int, laneLen:Int):Int {
        var j64 = Int64.make(0, j1);
        var sq = Int64.mul(j64, j64);
        var x = sq.high;
        var r64 = Int64.make(0, refArea);
        var x64 = Int64.make(0, x);
        var prod = Int64.mul(r64, x64);
        var y = prod.high;
        var zz = refArea - 1 - y;
        if (zz < 0) zz = 0;
        if (zz >= refArea) zz = refArea - 1;
        
        var start = 0;
        if (pass != 0) {
            start = (slice == SYNC_POINTS - 1) ? 0 : ((slice + 1) * segLen);
        }
        return (start + zz) % laneLen;
    }

    static function fillBlock(prev:Vector<Int64>, ref:Vector<Int64>, next:Vector<Int64>, xorMode:Bool) {
        var r = new Vector<Int64>(QWORDS_IN_BLOCK);
        var z = new Vector<Int64>(QWORDS_IN_BLOCK);
        for (i in 0...QWORDS_IN_BLOCK) {
            r[i] = Int64.xor(prev[i], ref[i]);
            z[i] = r[i];
        }

        for (row in 0...8) {
            var o = row * 16;
            applyP(z, o, o+1, o+2, o+3, o+4, o+5, o+6, o+7, o+8, o+9, o+10, o+11, o+12, o+13, o+14, o+15);
        }

        for (col in 0...8) {
            var c = col * 2;
            applyP(z, c, c+1, c+16, c+17, c+32, c+33, c+48, c+49, c+64, c+65, c+80, c+81, c+96, c+97, c+112, c+113);
        }

        for (i in 0...QWORDS_IN_BLOCK) {
            if (xorMode) next[i] = Int64.xor(next[i], Int64.xor(z[i], r[i]));
            else next[i] = Int64.xor(z[i], r[i]);
        }
    }

    static function applyP(v:Vector<Int64>, v0:Int, v1:Int, v2:Int, v3:Int, v4:Int, v5:Int, v6:Int, v7:Int, v8:Int, v9:Int, v10:Int, v11:Int, v12:Int, v13:Int, v14:Int, v15:Int) {
        gb(v, v0, v4, v8, v12);
        gb(v, v1, v5, v9, v13);
        gb(v, v2, v6, v10, v14);
        gb(v, v3, v7, v11, v15);
        gb(v, v0, v5, v10, v15);
        gb(v, v1, v6, v11, v12);
        gb(v, v2, v7, v8, v13);
        gb(v, v3, v4, v9, v14);
    }

    static function gb(v:Vector<Int64>, a:Int, b:Int, c:Int, d:Int) {
        v[a] = Int64.add(Int64.add(v[a], v[b]), fBlaMka(v[a], v[b]));
        v[d] = rotr(Int64.xor(v[d], v[a]), 32);
        v[c] = Int64.add(Int64.add(v[c], v[d]), fBlaMka(v[c], v[d]));
        v[b] = rotr(Int64.xor(v[b], v[c]), 24);
        v[a] = Int64.add(Int64.add(v[a], v[b]), fBlaMka(v[a], v[b]));
        v[d] = rotr(Int64.xor(v[d], v[a]), 16);
        v[c] = Int64.add(Int64.add(v[c], v[d]), fBlaMka(v[c], v[d]));
        v[b] = rotr(Int64.xor(v[b], v[c]), 63);
    }

    static inline function fBlaMka(x:Int64, y:Int64):Int64 {
        var m = Int64.make(0, 0xFFFFFFFF);
        return Int64.shl(Int64.mul(Int64.and(x, m), Int64.and(y, m)), 1);
    }

    static inline function rotr(x:Int64, n:Int):Int64 {
        return Int64.or(Int64.ushr(x, n), Int64.shl(x, 64 - n));
    }

    static function bytesToBlock(inp:Bytes, blk:Vector<Int64>) {
        for (i in 0...QWORDS_IN_BLOCK) {
            var o = i * 8;
            var lo = (inp.get(o)&0xFF)|((inp.get(o+1)&0xFF)<<8)|((inp.get(o+2)&0xFF)<<16)|((inp.get(o+3)&0xFF)<<24);
            var hi = (inp.get(o+4)&0xFF)|((inp.get(o+5)&0xFF)<<8)|((inp.get(o+6)&0xFF)<<16)|((inp.get(o+7)&0xFF)<<24);
            blk[i] = Int64.make(hi, lo);
        }
    }

    static function blockToBytes(blk:Vector<Int64>):Bytes {
        var out = Bytes.alloc(BLOCK_SIZE);
        for (i in 0...QWORDS_IN_BLOCK) {
            var o = i * 8;
            var lo = blk[i].low;
            var hi = blk[i].high;
            out.set(o, lo & 0xFF);
            out.set(o + 1, (lo >>> 8) & 0xFF);
            out.set(o + 2, (lo >>> 16) & 0xFF);
            out.set(o + 3, (lo >>> 24) & 0xFF);
            out.set(o + 4, hi & 0xFF);
            out.set(o + 5, (hi >>> 8) & 0xFF);
            out.set(o + 6, (hi >>> 16) & 0xFF);
            out.set(o + 7, (hi >>> 24) & 0xFF);
        }
        return out;
    }

    static inline function writeLE32(b:Bytes, o:Int, v:Int) {
        b.set(o, v & 0xFF);
        b.set(o + 1, (v >>> 8) & 0xFF);
        b.set(o + 2, (v >>> 16) & 0xFF);
        b.set(o + 3, (v >>> 24) & 0xFF);
    }

    static function intToBytes(v:Int):Bytes {
        var b = Bytes.alloc(4);
        b.set(0, v & 0xFF);
        b.set(1, (v >>> 8) & 0xFF);
        b.set(2, (v >>> 16) & 0xFF);
        b.set(3, (v >>> 24) & 0xFF);
        return b;
    }
}