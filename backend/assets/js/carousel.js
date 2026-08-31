/*=============== SWIPER CAROUSEL ===============*/
document.addEventListener('DOMContentLoaded', function () {
    // Initialize Swiper
    var swiper = new Swiper(".mySwiper", {
        slidesPerView: 1,
        spaceBetween: 0,
        loop: true,
        pagination: {
            el: ".swiper-pagination",
            clickable: true,
        },
        navigation: {
            nextEl: ".swiper-button-next",
            prevEl: ".swiper-button-prev",
        },
    });

    /*=============== PREDICT CAROUSEL IMAGE LOGIC ===============*/
    function predict(swiperInstance) {
        var activeSlide = swiperInstance.slides[swiperInstance.activeIndex];
        var legend = activeSlide.querySelector('.monitoring__slide-text');
        var img = activeSlide.querySelector('img');
        
        if (!legend || !img) return;
        
        var imgSrc = img.src;
        var imageName = imgSrc.split('/').pop();

        legend.textContent = 'Processing...';

        fetch('/predict_carousel_image', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ image_name: imageName })
        })
        .then(response => response.json())
        .then(data => {
            if (data.prediction) {
                legend.textContent = data.prediction;
            } else {
                legend.textContent = data.error || 'Error';
            }
        })
        .catch(error => {
            console.error('Prediction Error:', error);
            legend.textContent = 'Prediction failed';
        });
    }

    // Predict on slide change
    swiper.on('slideChange', function () {
        predict(swiper);
    });

    // Predict on initial load
    if (swiper.slides.length > 0) {
        predict(swiper);
    }

    /*=============== FIRE DETECTION FORM LOGIC ===============*/
    const uploadForm = document.querySelector('.monitoring__form-upload');
    const fileInput = document.getElementById('fire_image');
    const fileInputText = document.querySelector('.monitoring__file-input-text');

    if (fileInput) {
        // Show selected file name
        fileInput.addEventListener('change', function() {
            if (fileInput.files.length > 0) {
                fileInputText.textContent = `Selected: ${fileInput.files[0].name}`;
            } else {
                fileInputText.textContent = 'Click to select an image';
            }
        });
    }

    if (uploadForm) {
        // Handle form submission
        uploadForm.addEventListener('submit', function(event) {
            event.preventDefault();
            
            const formData = new FormData(uploadForm);
            fileInputText.textContent = 'Analyzing...';

            fetch('/detect_fire', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.result) {
                    fileInputText.textContent = data.result;
                } else {
                    fileInputText.textContent = data.error || 'An unknown error occurred.';
                }
            })
            .catch(error => {
                console.error('Detection Error:', error);
                fileInputText.textContent = 'Upload failed. See console for details.';
            });
        });
    }

    /*=============== MANUAL REPORT FORM LOGIC ===============*/
    const reportForm = document.querySelector('.monitoring__form-report');
    
    if (reportForm) {
        reportForm.addEventListener('submit', function(event) {
            // Optional: Add validation or processing logic here
            // Example: Clear success message after submission
            console.log('Report submitted');
        });
    }
});