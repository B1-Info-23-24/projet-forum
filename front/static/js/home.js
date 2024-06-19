document.addEventListener('DOMContentLoaded', function () {
	// Fonction pour charger les messages depuis l'API
	function loadPosts() {
			fetch('/posts')
					.then(response => response.json())
					.then(posts => {
							const postsContainer = document.querySelector('.posts');
							postsContainer.innerHTML = ''; // Effacer le contenu actuel

							posts.forEach(post => {
									const postElement = document.createElement('div');
									postElement.classList.add('post');
									postElement.innerHTML = `
											<div class="author">${post.author} • ${post.date}</div>
											<div class="text">${post.content}</div>
											<div class="tags">
													${post.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
											</div>
											<div class="stats">
													<span>${post.views} Vues</span>
													<span>${post.likes} J'aime</span>
													<span>${post.comments} commentaires</span>
											</div>
									`;
									postsContainer.appendChild(postElement);
							});
					})
					.catch(error => {
							console.error('Failed to load posts:', error);
					});
	}

	// Charger les messages au chargement de la page
	loadPosts();

	// Gérer la soumission du formulaire de publication
	const postForm = document.querySelector('.post-box textarea');
	const submitButton = document.querySelector('.post-box button');

	submitButton.addEventListener('click', function (event) {
			event.preventDefault();

			const content = postForm.value;
			if (content.trim() === '') {
					alert('Veuillez entrer un message');
					return;
			}

			const postData = {
					author: 'John Doe', // Vous pouvez remplacer par le nom de l'utilisateur actuel
					content: content,
					tags: ['Moto', 'Discussion'], // Tags par défaut
					date: new Date().toLocaleDateString(), // Date actuelle
					views: 0,
					likes: 0,
					comments: 0
			};

			// Envoyer les données au serveur
			fetch('/posts', {
					method: 'POST',
					headers: {
							'Content-Type': 'application/json'
					},
					body: JSON.stringify(postData)
			})
					.then(response => {
							if (response.ok) {
									// Recharger les messages après la publication
									loadPosts();
									postForm.value = ''; // Effacer le contenu du formulaire après la publication
							} else {
									throw new Error('Failed to submit post');
							}
					})
					.catch(error => {
							console.error('Error submitting post:', error);
							alert('Failed to submit post. Please try again later.');
					});
	});
});
