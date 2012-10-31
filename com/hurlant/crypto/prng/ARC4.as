/**
 * ARC4
 *
 * An ActionScript 3 implementation of RC4
 * Copyright (c) 2007 Henri Torgemane
 *
 * Derived from:
 * 		The jsbn library, Copyright (c) 2003-2005 Tom Wu
 *
 * See LICENSE.txt for full license information.
 */
package com.hurlant.crypto.prng
{
	import com.hurlant.crypto.symmetric.IStreamCipher;
	import com.hurlant.util.Memory;
	import flash.events.Event;
	import flash.events.EventDispatcher;
	import flash.events.TimerEvent;
	import flash.utils.getTimer;
	import flash.utils.Timer;
	
	import flash.utils.ByteArray;
	[Event(name="complete",type="flash.events.Event")]
	
	public class ARC4 extends EventDispatcher implements IPRNG, IStreamCipher
	{
		private var i:int = 0;
		private var j:int = 0;
		private var S:ByteArray;
		private const psize:uint = 256;
		private var timer:Timer;
		private var index:int;
		
		private var asyncTime:uint;
		private var asyncBytes:ByteArray;
		
		public function ARC4(key:ByteArray = null)
		{
			S = new ByteArray;
			timer = new Timer(1, 1);
			timer.addEventListener(TimerEvent.TIMER, onTimerHandler);
			if (key)
			{
				init(key);
			}
		}
		
		private function onTimerHandler(event:TimerEvent):void
		{
			parseBytes();
		}
		
		public function getPoolSize():uint
		{
			return psize;
		}
		
		public function init(key:ByteArray):void
		{
			var i:int;
			var j:int;
			var t:int;
			for (i = 0; i < 256; ++i)
			{
				S[i] = i;
			}
			j = 0;
			for (i = 0; i < 256; ++i)
			{
				j = (j + S[i] + key[i % key.length]) & 255;
				t = S[i];
				S[i] = S[j];
				S[j] = t;
			}
			this.i = 0;
			this.j = 0;
		}
		
		public function next():uint
		{
			var t:int;
			i = (i + 1) & 255;
			j = (j + S[i]) & 255;
			t = S[i];
			S[i] = S[j];
			S[j] = t;
			return S[(t + S[i]) & 255];
		}
		
		public function getBlockSize():uint
		{
			return 1;
		}
		
		public function encrypt(block:ByteArray):void
		{
			var i:uint = 0;
			while (i < block.length)
			{
				block[i++] ^= next();
			}
		}
		
		public function asyncEncrypt(block:ByteArray):void
		{
			index = 0;
			asyncBytes = block;
			timer.start();
		}
		
		private function parseBytes():void
		{
			asyncTime = getTimer();
			while (index < asyncBytes.length && getTimer() - asyncTime < 200)
			{
				asyncBytes[index++] ^= next();
			}
			if (index < asyncBytes.length)
			{
				timer.reset();
				timer.start();
			}
			else
			{
				dispatchEvent(new Event(Event.COMPLETE));
			}
		}
		
		public function asyncDecrypt(block:ByteArray):void
		{
			asyncEncrypt(block);
		}
		
		public function decrypt(block:ByteArray):void
		{
			encrypt(block); // the beauty of XOR.
		}
		
		public function dispose():void
		{
			var i:uint = 0;
			if (S != null)
			{
				for (i = 0; i < S.length; i++)
				{
					S[i] = Math.random() * 256;
				}
				S.length = 0;
				S = null;
			}
			this.i = 0;
			this.j = 0;
			Memory.gc();
		}
		
		override public function toString():String
		{
			return "rc4";
		}
	}
}