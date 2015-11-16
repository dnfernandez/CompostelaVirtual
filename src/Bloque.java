public class Bloque implements java.io.Serializable{
    private String nombre;
    private byte[] contenido;

    public Bloque() {
    }

    
    public Bloque(String nombre, byte[] contenido) {
        this.nombre = nombre;
        this.contenido = contenido;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    
    
    public byte[] getContenido() {
        return contenido;
    }

    public void setContenido(byte[] contenido) {
        this.contenido = contenido;
    }

    public String toString() {
	if (contenido != null) {
        	return this.nombre+": ["+contenido.length+" posiciones]";
	}
	else {
        	return this.nombre+": [vacio]";
	}
    }
        
}
