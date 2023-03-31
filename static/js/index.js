const boton = document.querySelector('.button')
const verdatos = document.querySelector('.button-verdatos')

boton.addEventListener('click', () => {
    fetch('/analizar_red', { method: 'POST' })
        .then(response => {
            if (response.ok) {
                alert('Analizando...');
            } else {
                alert('Error al ejecutar el código');
            }
        })

})

verdatos.addEventListener('click', () => {
    fetch('/ver_datos', { method: 'GET' })
        .then(response => console.log(response.formData))
})

