// Espera a que el contenido del DOM esté cargado
document.addEventListener('DOMContentLoaded', () => {
  const inputBusqueda = document.getElementById('busqueda');
  const tarjetas = document.querySelectorAll('.app-card');

  inputBusqueda.addEventListener('input', () => {
    const texto = inputBusqueda.value.toLowerCase();

    tarjetas.forEach(tarjeta => {
      const nombre = tarjeta.querySelector('h2').textContent.toLowerCase();
      const descripcion = tarjeta.querySelector('p').textContent.toLowerCase();

      if (nombre.includes(texto) || descripcion.includes(texto)) {
        tarjeta.style.display = 'block';
      } else {
        tarjeta.style.display = 'none';
      }
    });
  });
});
