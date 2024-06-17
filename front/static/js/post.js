async function fetchPosts() {
	try {
			const response = await fetch('http://localhost:8181/getpost');
			if (!response.ok) {
					throw new Error('Network response was not ok ' + response.statusText);
			}
			const posts = await response.json();

			const container = document.getElementById('posts-container');
			container.innerHTML = ''; 
			posts.forEach(post => {
					const postDiv = document.createElement('div');
					postDiv.className = 'post';

					const content = document.createElement('p');
					content.textContent = post.content;

					const author = document.createElement('p');
					author.textContent = `Author: ${post.user_id}`;

					const date = document.createElement('p');
					date.textContent = `Date: ${post.created_at}`;

					postDiv.appendChild(content);
					postDiv.appendChild(author);
					postDiv.appendChild(date);
					container.appendChild(postDiv);
			});
	} catch (error) {
			console.error('Fetch error: ', error);
			const container = document.getElementById('posts-container');
			container.innerHTML = '<p>Error fetching posts. Please try again later.</p>';
	}
}

window.onload = fetchPost;
