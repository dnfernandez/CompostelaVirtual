
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 *
 * @author ribadas
 */
public class JSONUtils {

    /**
     * Parsea una cadena en el formato JSON simplificado y devuelve los pares clave-valor en un Map<String,String>
     */
    public static Map<String, String> json2map(String json) {
        Map<String, String> resultado = new HashMap<String, String>();
        int inicio = json.indexOf("{");
        int fin = json.indexOf("}");
        if ((inicio != -1) && (fin != -1) && (inicio < fin)) {
            String contenido = json.substring((inicio + 1), fin).trim();
            String[] entradas = contenido.split("\\s*,\\s*"); // Separar por ","
            for (String entrada : entradas) {
                String[] par = entrada.trim().split("\\s*:\\s*", 2); // Separar por ";"
                resultado.put(par[0].replace("\"", ""), par[1].replace("\"", ""));
            }
        }
        return resultado;
    }

    /**
     * Crea una cadena en formato JSON simplificado a partir de los pares clave-valor de un Map<String,String>
     * Si es necesario, omite los caracteres "especiales" presentes en claves y valores
     */
    public static String map2json(Map<String, String> datos) {
        StringBuilder resultado = new StringBuilder();
        resultado.append('{');
        if (datos != null) {
            for (Map.Entry<String, String> entrada : datos.entrySet()) {
                if (resultado.length() > 1) { // Anadir separador ","
                    resultado.append(',');
                }
                resultado.append('\"');
                resultado.append(limpiarCadena(entrada.getKey()));
                resultado.append('\"');
                resultado.append(':');
                resultado.append('\"');
                resultado.append(limpiarCadena(entrada.getValue()));
                resultado.append('\"');
            }
        }
        resultado.append('}');
        return resultado.toString();
    }

    /**
     * TRAMPA: Elimina caracteres del formato JSON simplificado ('{' '}' ',' ':' '"') para facilitar el parseo
     */
    private static String limpiarCadena(String cadena) {
        return cadena.replaceAll("\\{|\\}|:|,|\\\"", "");
    }

    /**
     * Ejemplos de uso
     */
    public static final void main(String[] args) {
        System.out.println("* Crear una cadena en formato JSON simplificado");

        Map<String, String> datos = new HashMap<String, String>();
        //datos.put("nombre", "alumnos de ssi");
        //datos.put("fecha", "septiembre-2014");
        //datos.put("lugar", "ESEI, ourense");

        /* OJO: System.console() no funciona desde los IDEs (desde linea de comandos no hay problema)
        String nombre = System.console().readLine("Nombre : ");
        datos.put("nombre", nombre);
        String fecha = System.console().readLine("Fecha  : ");
        datos.put("fecha", fecha);
        String lugar = System.console().readLine("Lugar  : ");
        datos.put("lugar", lugar);
        */
        Scanner in = new Scanner(System.in);
        System.out.print("Nombre : ");
        String nombre = in.nextLine();
        datos.put("nombre", nombre);
        
        System.out.print("Fecha  : ");
        String fecha = in.nextLine();        
        datos.put("fecha", fecha);
        
        System.out.print("Lugar  : ");
        String lugar = in.nextLine();
        datos.put("lugar", lugar);
        in.close();
        

        String json = JSONUtils.map2json(datos);
        System.out.println("JSON: " + json);

        System.out.println("* Parsear el JSON simplificado resultante para extraer un Map con pares clave-valor");

        Map<String, String> datos2 = JSONUtils.json2map(json);
        System.out.print("MAP: ");
        for (Map.Entry<String, String> entrada : datos2.entrySet()) {
            System.out.print(entrada.getKey() + "->" + entrada.getValue() + " ");
        }
        System.out.println();

    }

}
