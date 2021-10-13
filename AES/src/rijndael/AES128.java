package rijndael;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class AES128 {
	
	private static int iterations;
	private static int rounds;
	
	private static byte[][] state = new byte[4][4];
	private static byte[][] key = new byte[4][4];
	
	public AES128() {}
	
	public static String byteToHex(byte b) {
	    int i = b & 0xFF;
	    return Integer.toHexString(i);
	  }
	
	public static void main(String args[]) throws FileNotFoundException {
		System.out.print("Please type the file name: ");
		Scanner sc = new Scanner(System.in);
		Scanner reader = new Scanner(new File(sc.nextLine()));
		sc.close();
		
		iterations = reader.nextInt();
		rounds = reader.nextInt();
		reader.nextLine();
		
		String keyStr = reader.nextLine();
		String stateStr = reader.nextLine();
		
	    byte[] stateTemp = new byte[16];
	    byte[] keyTemp = new byte[16];
	    
	    for (int i = 0; i < stateTemp.length; i++) {
	      int index = i * 2;
	      int v = Integer.parseInt(stateStr.substring(index, index + 2), 16);
	      stateTemp[i] = (byte) v;
	      
	      int index2 = i * 2;
	      int w = Integer.parseInt(keyStr.substring(index2, index2 + 2), 16);
	      keyTemp[i] = (byte) w;
	    }
		
		for (int col=0; col < 4; col++) {
		    for (int row=0; row < 4; row++) {
		    	state[row][col] = stateTemp[row + 4*col];
		    	key[row][col] = keyTemp[row + 4*col];
		    }
		}
		reader.close();
		
		byte[][] startState = new byte [4][4];
		byte[][] startKey = new byte[4][4];
		for (int col=0; col < 4; col++) {
		    for (int row=0; row < 4; row++) {
		    	startState[row][col] = state[row][col];
		    	startKey[row][col] = key[row][col];
		    }
		}
		
		for(int iter = 0; iter < iterations; iter++) {
			
			for (int col=0; col < 4; col++) {
			    for (int row=0; row < 4; row++) {
			    	key[row][col] = startKey[row][col];
			    }
			}
			if(iter != 0) {
				for(int i = 0; i<4; i++) {
					state[i] = xOr(state[i], startState[i]);
				}
			}
			
			addRoundKey(key);
			for(int curRound = 0; curRound < rounds-1; curRound++) {
				byteSub();
				shiftRow();
				mixColumns();
				key = nextKey(key, curRound);
				addRoundKey(key);
			}

			byteSub();
			shiftRow();
			key = nextKey(key, rounds-1);
			addRoundKey(key);
		}
		
		System.out.println("The Ciphertext is:");
		for(int col = 0; col<4; col++)
			for(int row = 0; row<4; row++) {
				byte val = state[row][col];
				int test = val;
				
				if(val<0) {test+=256;}
				if(test<16)
					System.out.print("0");
				System.out.print(byteToHex(val));
		}
	}
	
	private static void addRoundKey(byte[][] input) {
		for (int row=0; row < 4; row++) {
		    for (int col=0; col < 4; col++) {
		    	state[row][col] ^= input[row][col];
		    }
		}
	}
	
	private static void byteSub() {
		
		for (int row=0; row < 4; row++) {
		    for (int col=0; col < 4; col++) {
		    	int index = state[row][col];
		    	if(index<0) {index += 256;}
		    	
		    	state[row][col] = (byte) Tables.S_BOX[index];
		    }
		}
	}
	
	private static void shiftRow() {
		byte[][] temp = new byte[4][4];
		
		for(int row = 0; row<4; row++) {
			for(int col = 0; col<4; col++) {
				temp[row][col] = state[row][col];
			}
		}
		
		for(int row = 0; row<4; row++) {
			for(int col = 0; col<4; col++) {
				state[row][col] = temp[row][(col+row)%4];
			}
		}
	}
	
	private static void mixColumns() {
		byte a, b, c, d;
		a=3;b=1;c=1;d=2;
		
		
		byte[][] input = state;
		int[] temp = new int[4];
		for (int i = 0; i < 4; i++) {
			temp[0] = multiply(d, input[0][i]) ^ multiply(a, input[1][i])
					^ multiply(b, input[2][i]) ^ multiply(c, input[3][i]);
			temp[1] = multiply(c, input[0][i]) ^ multiply(d, input[1][i])
					^ multiply(a, input[2][i]) ^ multiply(b, input[3][i]);
			temp[2] = multiply(b, input[0][i]) ^ multiply(c, input[1][i])
					^ multiply(d, input[2][i]) ^ multiply(a, input[3][i]);
			temp[3] = multiply(a, input[0][i]) ^ multiply(b, input[1][i])
					^ multiply(c, input[2][i]) ^ multiply(d, input[3][i]);
			for (int j = 0; j < 4; j++)
				input[j][i] = (byte) (temp[j]);
		}
		state = input;
	}
	
	private static byte multiply(byte a, byte b) {
		byte returnValue = 0;
		byte temp = 0;
		while (a != 0) {
			if ((a & 1) != 0)
				returnValue = (byte) (returnValue ^ b);
			temp = (byte) (b & 0x80);
			b = (byte) (b << 1);
			if (temp != 0)
				b = (byte) (b ^ 0x1b);
			a = (byte) ((a & 0xff) >> 1);
		}
		return returnValue;
	}
	
	private static byte[][] nextKey(byte[][] temp, int round) {
		byte[][] curKey = new byte[4][4];
		for(int row = 0; row<4; row++) {
			for(int col = 0; col<4; col++) {
				curKey[row][col] = temp[col][row];
			}
		}
		
		byte[][] newKey = new byte[4][4];
		byte[] rcon = {(byte) Tables.RCON[round], 0, 0, 0};
		
		for(int i = 0; i<4; i++) {
			int index = curKey[3][(i+1)%4];
	    	if(index<0) {index += 256;}
	    	
	    	newKey[0][i] = (byte) Tables.S_BOX[index];
		}
		newKey[0] = xOr(newKey[0], curKey[0]);
		newKey[0] = xOr(newKey[0], rcon);
		
		for(int i = 1; i<4; i++) {
			newKey[i] = xOr(newKey[i-1], curKey[i]);
		}
		
				for(int row = 0; row<4; row++) {
					for(int col = 0; col<4; col++) {
						temp[row][col] = newKey[col][row];
					}
				}
				return temp;
	}
	
	private static byte[] xOr(byte[] a, byte[] b) {
		byte[] c = new byte[4];
		for (int i=0; i < 4; i++) {
	    	c[i] = (byte) (a[i]^b[i]);
	    }
		return c;
	}
}
