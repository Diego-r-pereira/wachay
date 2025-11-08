document.addEventListener('DOMContentLoaded', function() {
    const carousel = document.querySelector('.carousel');
    const prevButton = document.querySelector('.prev');
    const nextButton = document.querySelector('.next');
    const items = document.querySelectorAll('.carousel-item');
    const totalItems = items.length;
    let index = 0;

    if (nextButton) {
        nextButton.addEventListener('click', () => {
            index = (index + 1) % totalItems;
            updateCarousel();
        });
    }

    if (prevButton) {
        prevButton.addEventListener('click', () => {
            index = (index - 1 + totalItems) % totalItems;
            updateCarousel();
        });
    }

    function updateCarousel() {
        carousel.style.transform = `translateX(-${index * 100}%)`;
        const currentImage = items[index].querySelector('img').src;
        predictImage(currentImage);
    }

    function predictImage(image) {
        fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({image: image})
        })
        .then(response => response.json())
        .then(data => {
            if (data.fire) {
                reportButton.style.display = 'block';
            } else {
                reportButton.style.display = 'none';
            }
        });
    }
});
