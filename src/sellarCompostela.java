import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class sellarCompostela {

	private static String nombreAlbergue;
	private static PrivateKey clavePrivadaAlbergue;
	private static Paquete compostela;
	private static Map<String, String> datos;
	private static byte[] datosCifrados;
	private static byte[] firmaPeregrino;

	// getters
	public static byte[] getDatosCifrados() {
		return datosCifrados;
	}

	private static void crearAlbergue() {
		datos = new HashMap<String, String>();
		pedirDatos();

	}

	private static void pedirDatos() {

		Scanner in = new Scanner(System.in);
		System.out.print("Nombre: ");
		datos.put("N", in.nextLine());
		System.out.print("Fecha: ");
		datos.put("F", in.nextLine());
		System.out.print("Lugar: ");
		datos.put("L", in.nextLine());
		System.out.print("Incidencias: ");
		datos.put("I", in.nextLine());
		in.close();

	}

	private static byte[] formatearJSON() {
		String json = JSONUtils.map2json(datos);
		return json.getBytes();
	}

	private static void cifrarDatos() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Bloque bloquefirma = compostela.getBloque("FIRMA_PEREGRINO");
		firmaPeregrino = bloquefirma.getContenido();
		byte[] arrayDatos = formatearJSON();

		MessageDigest messageDigest = MessageDigest.getInstance("MD5", "BC");
		messageDigest.update(firmaPeregrino);
		messageDigest.update(arrayDatos);
		byte[] datos = messageDigest.digest();

		Cipher cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivadaAlbergue);
		byte[] bufferCifrado = cifrador.doFinal(datos);
		datosCifrados = bufferCifrado;

	}

	public static void obtenerArgumentos(String comp, String cla) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream fileIn = new FileInputStream(comp);
		ObjectInputStream entrada = new ObjectInputStream(fileIn);
		compostela = (Paquete) entrada.readObject();
		entrada.close();

		byte[] bufferPriv = new byte[5000];
		FileInputStream in = new FileInputStream(cla);
		in.read(bufferPriv, 0, 5000);
		in.close();
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
		clavePrivadaAlbergue = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
	}

	private static void mensajeAyuda() {
		System.out.println(
				"\tSintaxis:   java sellarCompostela <nombrePaquete> <identificadorAlbergue> <ficheros_claves_necesarias>");
		System.out.println();
	}

	public static void mostrarBytes(byte[] buffer) {
		System.out.write(buffer, 0, buffer.length);
	}

	public static void main(String[] args) throws Exception {
		// Comprobar argumentos
		if (args.length != 3) {
			mensajeAyuda();
			System.exit(1);
		}

		/**
		 * Obtenemos el nombre del albergue y guardamos el paquete de la
		 * compostela del peregrino y la clave privada del albergue
		 **/
		nombreAlbergue = args[1];
		obtenerArgumentos(args[0], args[2]);
		/** Creamos el albergue con sus datos **/
		crearAlbergue();
		/**
		 * Creamos firma del albergue mediante la firma del peregrino y los
		 * datos del albergue y los ciframos con encriptación RSA mediante la
		 * clave privada del albergue
		 **/
		cifrarDatos();

		/**
		 * Creamos los bloques con los datos del albergue y la firma del
		 * albergue y añadimos los bloques a la compostela del peregrino
		 **/

		// Bloque firma albergue
		Bloque datosCifradosAlbergue = new Bloque();
		datosCifradosAlbergue.setNombre("Firma_" + nombreAlbergue);
		datosCifradosAlbergue.setContenido(getDatosCifrados());
		compostela.anadirBloque(datosCifradosAlbergue);
		
		//Bloque datos visibles del albergue
		Bloque datosVisiblesAlbergue = new Bloque();
		datosVisiblesAlbergue.setNombre("Datos Visibles_" + nombreAlbergue);
		datosVisiblesAlbergue.setContenido(formatearJSON());
		compostela.anadirBloque(datosVisiblesAlbergue);

		System.out.println("\nBloques existentes en paquete compostela: ");
		Iterator<String> it = compostela.getNombresBloque().iterator();
		while (it.hasNext())
			System.out.println(it.next());

		/** Guardamos el paquete(objeto) creado en un fichero **/
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[0]));
		out.writeObject(compostela);
		out.close();
		System.out.println("\nActualizado paquete: " + args[0]);

	}

}
