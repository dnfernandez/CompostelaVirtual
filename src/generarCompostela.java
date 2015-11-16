import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class generarCompostela {

	private static String nombrePaquete;
	private static PrivateKey clavePrivadaPeregrino;
	private static PublicKey clavePublicaOficina;
	private static Map<String, String> datos;
	private static byte[] datosCifrados;
	private static byte[] claveSecretaCifrada;
	private static byte[] firmaPeregrino;

	private static SecretKey claveSecreta;

	// getters
	public static byte[] getDatosCifrados() {
		return datosCifrados;
	}

	public static byte[] getClaveSecretaCifrada() {
		return claveSecretaCifrada;
	}

	public static byte[] getFirmaPeregrino() {
		return firmaPeregrino;
	}

	private static void crearPeregrino() {
		datos = new HashMap<String, String>();
		pedirDatos();

	}

	private static void pedirDatos() {

		Scanner in = new Scanner(System.in);
		System.out.print("Nombre : ");
		datos.put("nombre", in.nextLine());
		System.out.print("Dni : ");
		datos.put("dni", in.nextLine());
		System.out.print("Domicilio : ");
		datos.put("domicilio", in.nextLine());
		System.out.print("Fecha : ");
		datos.put("fecha", in.nextLine());
		System.out.print("Lugar : ");
		datos.put("lugar", in.nextLine());
		System.out.print("Motivaciones : ");
		datos.put("motivaciones", in.nextLine());
		in.close();

	}

	private static byte[] formatearJSON() {
		String json = JSONUtils.map2json(datos);
		return json.getBytes();
	}

	private static void generarClaveAleatoria() throws Exception {
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);
		claveSecreta = generadorDES.generateKey();
	}

	private static void cifrarDatos() throws Exception {
		byte[] bufferCifrado;
		byte[] arrayDatos = formatearJSON();

		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, claveSecreta);
		bufferCifrado = cifrador.doFinal(arrayDatos);
		datosCifrados = bufferCifrado;
	}

	private static void cifrarClaveSecreta() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Cipher cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaOficina);
		String encodedKey = Base64.getEncoder().encodeToString(claveSecreta.getEncoded());
		byte[] buffer = encodedKey.getBytes();
		claveSecretaCifrada = cifrador.doFinal(buffer);
	}

	public static void generarFirma() throws Exception {
		byte[] datos = formatearJSON();
		MessageDigest messageDigest = MessageDigest.getInstance("MD5", "BC");
		datos = messageDigest.digest(datos);
		Cipher cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivadaPeregrino);
		firmaPeregrino = cifrador.doFinal(datos);
	}

	private static void mensajeAyuda() {
		System.out.println(
				"\tSintaxis:   java generarCompostela <nombrePaquete> <fichero_KRperegrino> <fichero_KUoficina>");
		System.out.println();
	}

	public static void mostrarBytes(byte[] buffer) {
		System.out.write(buffer, 0, buffer.length);
	}

	public static void obtenerClaves(String KR, String KO) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		byte[] bufferPriv = new byte[5000];
		FileInputStream in = new FileInputStream(KR);
		in.read(bufferPriv, 0, 5000);
		in.close();
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
		clavePrivadaPeregrino = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

		byte[] bufferPublic = new byte[5000];
		FileInputStream KUO = new FileInputStream(KO);
		KUO.read(bufferPublic, 0, 5000);
		KUO.close();
		KeyFactory keyFactoryRSA1 = KeyFactory.getInstance("RSA", "BC");
		X509EncodedKeySpec clavePublicaOfic = new X509EncodedKeySpec(bufferPublic);
		clavePublicaOficina = keyFactoryRSA1.generatePublic(clavePublicaOfic);
	}

	public static void main(String[] args) throws Exception {
		// Comprobar argumentos
		if (args.length != 3) {
			mensajeAyuda();
			System.exit(1);
		}

		nombrePaquete = args[0];
		/**
		 * Guardamos claves privada peregrino y publica oficina en variables
		 **/
		obtenerClaves(args[1], args[2]);
		/** Creamos datos de peregrino **/
		crearPeregrino();
		/** Generamos clave secreta aleatoria para el cifrado DES **/
		generarClaveAleatoria();
		/** Ciframos los datos del peregrino mediante encriptacion DES **/
		cifrarDatos();
		/**
		 * Ciframos la clave secreta aleatoria con la clave publica de la
		 * oficina
		 **/
		cifrarClaveSecreta();
		/**
		 * Ciframos el resumen enviado mediante la clave privada del peregrino
		 **/
		generarFirma();

		/**
		 * Creamos el paquete (compostela) y añadimos los bloques de los datos
		 * cifrados, clave secreta cifrada y firma de peregrino
		 **/
		Paquete compostela = new Paquete();

		// Bloque de datos cifrados
		Bloque datosCifrados = new Bloque();
		datosCifrados.setNombre("Datos Cifrados");
		datosCifrados.setContenido(getDatosCifrados());
		compostela.anadirBloque(datosCifrados);

		// Bloque con clave secreta cifrada
		Bloque claveSecretaCifrada = new Bloque("Clave Secreta Cifrada", getClaveSecretaCifrada());
		compostela.anadirBloque(claveSecretaCifrada);

		// Bloque con firma peregrino
		Bloque firmaPeregrino = new Bloque("Firma Peregrino", getFirmaPeregrino());
		compostela.anadirBloque(firmaPeregrino);

		System.out.println("\nBloques existentes en paquete compostela: ");
		Iterator<String> it = compostela.getNombresBloque().iterator();
		while (it.hasNext())
			System.out.println(it.next());

		/** Guardamos el paquete(objeto) creado en un fichero **/
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(nombrePaquete));
		out.writeObject(compostela);
		out.close();
		System.out.println("\nCreado paquete: " + nombrePaquete);

	}

}
