import { generateAuthorizationUrl } from "./utils.js";


const accessToken = localStorage.getItem("access_token");
const contentWithToken = document.getElementById("contentWithToken");
const contentWithoutToken = document.getElementById("contentWithoutToken");
const buttonDiv = document.getElementById("buttonDiv");
const disconnectDiv = document.getElementById("disconnectDiv")

document.getElementById("hideForm").addEventListener("submit", function (event) {
    event.preventDefault();
    event.stopPropagation();

    if (accessToken) {
        const form = event.target;
        const spinner = document.getElementById("spinnerHide");
        spinner.style.display = "none";

        if (form.checkValidity()) {
            const imageFile = document.getElementById("encodeimage1").files[0];
            const message = document.getElementById("secretText").value.trim();
            const key = document.getElementById("secretKey1").value.trim();

            const formData = new FormData();
            formData.append("image", imageFile);
            formData.append("message", encodeURIComponent(message));
            formData.append("key", encodeURIComponent(key));

            spinner.style.display = "inline-block";
            fetch('http://api.localhost:8080/hide', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${accessToken}`  // Send access token for authorization
                },
                body: formData,
            })
                .then(response => {
                    setTimeout(() => {
                        spinner.style.display = "none";
                    }, 1000);
                    if (!response.ok) {
                        throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
                    }
                    return response.text();
                })
                .then(base64Image => {
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = base64Image;
                    a.download = 'hidden_message_image.png';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                })
                .catch(error => console.error('Error:', error));
        } else {
            form.classList.add('was-validated');
        }
    } else {
        contentDiv.innerHTML = "You need to be logged in to perform this action.";
    }
});

document.getElementById("extractForm").addEventListener("submit", function (event) {
    event.preventDefault();
    event.stopPropagation();

    if (accessToken) {
        const form = event.target;
        const spinner = document.getElementById("spinnerExtract");
        spinner.style.display = "none";

        if (form.checkValidity()) {
            const imageFile = document.getElementById("decodeimage2").files[0];
            const secretKey = document.getElementById("secretKey2").value.trim();

            const formData = new FormData();
            formData.append("image", imageFile);
            formData.append("key", encodeURIComponent(secretKey));

            spinner.style.display = "inline-block";
            fetch('http://api.localhost:8080/extract', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${accessToken}`  // Send access token for authorization
                },
                body: formData
            })
                .then(response => {
                    setTimeout(() => {
                        spinner.style.display = "none";
                    }, 1000);

                    if (!response.ok) {
                        throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
                    }
                    return response.text();
                })
                .then(data => {
                    const decodedText = data || "No message found.";
                    document.getElementById("decodedText").value = decodedText;
                })
                .catch(error => {
                    console.error('Error:', error);
                    const decodedTextElement = document.getElementById("decodedText");
                    decodedTextElement.value = "An error occurred during extraction...";
                    decodedTextElement.style.color = 'red';
                });
        } else {
            form.classList.add("was-validated");
        }
    } else {
        contentDiv.innerHTML = "You need to be logged in to perform this action.";
    }
});

if (accessToken) {
    buttonDiv.innerHTML = `Access Token = ${accessToken}`;

    contentWithoutToken.classList.remove(...contentWithoutToken.classList);
    contentWithoutToken.classList.add("d-none");
    buttonDiv.style.display="none";
    contentWithToken.style.display = "block";
    disconnectDiv.style.display="block";
    
    disconnectDiv.addEventListener('click', () => {
        // Supprimer le token d'accès du localStorage
        localStorage.removeItem("access_token");
        localStorage.removeItem("code_verifier");

        // Rediriger vers la même page pour réinitialiser l'état
        window.location.replace(window.location.origin);
    })

}
else {
    contentWithoutToken.style.display = "block";
    generateAuthorizationUrl()
        .then(authorizationUrl => {
            buttonDiv.addEventListener('click', () => {
                window.location.href = authorizationUrl;
            });
        })
        .catch(error => {
            console.error('Error during access token generation: ', error);
        });
}