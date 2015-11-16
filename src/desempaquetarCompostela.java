import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class desempaquetarCompostela {
	private static Paquete compostela;
	private static int numAlbergues;
	private static PrivateKey clavePrivadaOficina;
	private static PublicKey clavePublicaPeregrino;
	private static String[] idenAlb;
	private static PublicKey[] claveAlb;
	private static SecretKey claveSecreta;
	private static byte[] datosDescifrados;
	private static byte[] firmaDescifrada;
	private static Bloque firmaCifradaPeregrino;

	private static void comprobarPeregrino() throws Exception {
		try {
			/**
			 * Desciframos la clave secreta mediante la clave privada de la
			 * oficina
			 **/

			Bloque bloqueClaveSecreta = compostela.getBloque("CLAVE_SECRETA_CIFRADA");
			byte[] claveSecretaCifrada = bloqueClaveSecreta.getContenido();

			Security.addProvider(new BouncyCastleProvider());
			Cipher cifrador = Cipher.getInstance("RSA", "BC");
			cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaOficina);
			byte[] bufferPlano2 = cifrador.doFinal(claveSecretaCifrada);
			byte[] encodedKey = Base64.getDecoder().decode(bufferPlano2);
			claveSecreta = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");

			/** Desciframos los datos con la clave secreta **/
			Bloque bloqueDatos = compostela.getBloque("DATOS_CIFRADOS");
			byte[] datosCifrados = bloqueDatos.getContenido();
			Cipher cifrador2 = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cifrador2.init(Cipher.DECRYPT_MODE, claveSecreta);
			datosDescifrados = cifrador2.doFinal(datosCifrados);

			System.out.println("Peregrino verificado:");
			System.out.print("\tDatos:");
			mostrarBytes(datosDescifrados);
		} catch (Exception e) {
			System.out.println(
					"ERROR: no se puede cifrar/descifrar con las claves pasadas como argumento o el peregrino no es quien dice ser");
		}
	}

	private static void comprobarModificaciones() throws Exception {
		try {
			/** Crear firma peregrino con los datos descifrados **/
			byte[] datos = datosDescifrados;
			MessageDigest messageDigest = MessageDigest.getInstance("MD5", "BC");
			datos = messageDigest.digest(datos);

			/** Descifrar firma peregrino con KU peregrino **/
			Bloque bloqueFirma = compostela.getBloque("FIRMA_PEREGRINO");
			firmaCifradaPeregrino = bloqueFirma;
			byte[] firmaCifrada = bloqueFirma.getContenido();

			Security.addProvider(new BouncyCastleProvider());
			Cipher cifrador = Cipher.getInstance("RSA", "BC");
			cifrador.init(Cipher.DECRYPT_MODE, clavePublicaPeregrino);
			firmaDescifrada = cifrador.doFinal(firmaCifrada);

			if (Arrays.equals(datos, firmaDescifrada)) {
				System.out.println("\n\nLos datos no han sufrido modificaciones");
			} else {
				throw new Exception();
			}

			System.out.print("\tFirma descifrada: ");
			mostrarBytes(firmaDescifrada);
			System.out.print("\n\tFirma creada:     ");
			mostrarBytes(datos);
			System.out.println("\n\n");

		} catch (Exception e) {
			System.out.println("\n ERROR:Los datos han sufrido modificaciones");
		}
	}

	private static void comprobarAlbergues() throws Exception {
		try {
			for (int i = 0; i < numAlbergues; i++) {
				Bloque bloqueAlbergue = compostela.getBloque("FIRMA_" + idenAlb[i].toUpperCase());
				byte[] firmaAlbergue = bloqueAlbergue.getContenido();
				byte[] buffer;
				Security.addProvider(new BouncyCastleProvider());

				Cipher cifrador = Cipher.getInstance("RSA", "BC");
				cifrador.init(Cipher.DECRYPT_MODE, claveAlb[i]);
				buffer = cifrador.doFinal(firmaAlbergue);

				byte[] firmaPeregrino = firmaCifradaPeregrino.getContenido();
				byte[] datosVisibleArlbergue = compostela.getBloque("DATOS_VISIBLES_" + idenAlb[i].toUpperCase())
						.getContenido();

				MessageDigest messageDigest = MessageDigest.getInstance("MD5", "BC");
				messageDigest.update(firmaPeregrino);
				messageDigest.update(datosVisibleArlbergue);
				byte[] datos = messageDigest.digest();

				if (Arrays.equals(datos, buffer)) {
					System.out.println("El albergue \"" + idenAlb[i] + "\" es válido");
				} else {
					throw new Exception();
				}
				/*
				 * System.out.print("\n\tFirma descifrada: ");
				 * mostrarBytes(datos); System.out.print("\n\tFirma creada: ");
				 * mostrarBytes(buffer);
				 */
			}
		} catch (Exception e) {
			System.out.println("\nSello de albergue no válido");
		}

	}

	private static void obtenerArgumentos(String comp, String claKRO, String claKUP) throws Exception {
		//Obtenemos compostela
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream fileIn = new FileInputStream(comp);
		ObjectInputStream entrada = new ObjectInputStream(fileIn);
		compostela = (Paquete) entrada.readObject();
		entrada.close();
		
		//Obtenemos clave privada oficina
		byte[] bufferPriv = new byte[5000];
		FileInputStream in = new FileInputStream(claKRO);
		in.read(bufferPriv, 0, 5000);
		in.close();
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
		clavePrivadaOficina = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
		
		//Obtenemos clave publica peregrino
		byte[] bufferPublic = new byte[5000];
		FileInputStream KUP = new FileInputStream(claKUP);
		KUP.read(bufferPublic, 0, 5000);
		KUP.close();
		KeyFactory keyFactoryRSA1 = KeyFactory.getInstance("RSA", "BC");
		X509EncodedKeySpec clavePublicaPere = new X509EncodedKeySpec(bufferPublic);
		clavePublicaPeregrino = keyFactoryRSA1.generatePublic(clavePublicaPere);
		
		//Obtenemos claves publicas albergues y las guardamos en un array de claves
		byte[] bufferAlb;
		FileInputStream KUA;
		KeyFactory keyFactoryRSA2;
		X509EncodedKeySpec clavePublicaAlb;

		claveAlb = new PublicKey[numAlbergues];
		for (int i = 0; i < numAlbergues; i++) {
			bufferAlb = new byte[5000];
			KUA = new FileInputStream(idenAlb[i] + ".publica");
			KUA.read(bufferAlb, 0, 5000);
			KUA.close();
			keyFactoryRSA2 = KeyFactory.getInstance("RSA", "BC");
			clavePublicaAlb = new X509EncodedKeySpec(bufferAlb);
			claveAlb[i] = keyFactoryRSA2.generatePublic(clavePublicaAlb);
		}
	}

	private static void mensajeAyuda() {
		System.out.println(
				"\tSintaxis:   java desempaquetarCompostela <nombrePaquete> <numeroAlbergues> <identificador_Albergue1> <fichero_clave_Albergue1> ..."
						+ " <identificador_AlbergueN> <fichero_clave_AlbergueN> <ficheros_KR_oficina> <ficheros_KU_peregrino>");
		System.out.println();
	}

	private static void mostrarBytes(byte[] buffer) {
		System.out.write(buffer, 0, buffer.length);
	}

	public static void main(String[] args) throws Exception {
		// Comprobar argumentos
		if (args.length == 0) {
			mensajeAyuda();
			System.exit(1);
		}
		numAlbergues = Integer.parseInt(args[1]);
		if (args.length != 4 + numAlbergues * 2) {
			mensajeAyuda();
			System.exit(1);
		}
		/**
		 * Creamos array de Strings para contener el nombre de los albergues
		 **/
		idenAlb = new String[numAlbergues];
		for (int i = 0; i < numAlbergues; i++) {
			int n = 2 + 2 * i;
			idenAlb[i] = args[n];
		}
		/** Guardamos todos los argumentos en sus respectivas variables **/
		obtenerArgumentos(args[0], args[(2 + numAlbergues * 2)], args[(3 + numAlbergues * 2)]);

		/** Comprobamos si el peregrino es quien dice ser **/
		comprobarPeregrino();
		/**
		 * Comprobamos si existen modificaciones entre la firma cifrada de la
		 * compostela y la nueva firma creada
		 **/
		comprobarModificaciones();

		/**
		 * Comprobamos si el sello de los albergues es válido
		 **/

		comprobarAlbergues();
	}

}
