document.addEventListener('DOMContentLoaded', () => {
    const chatbotButton = document.querySelector('.chatbot__button');
    
    // Only run chatbot logic if the button exists on the page
    if (chatbotButton) {
        const chatbotWindow = document.querySelector('.chatbot__window');
        const chatbotClose = document.querySelector('.chatbot__close');
        const chatbotConversation = document.querySelector('.chatbot__conversation');
        const chatbotInput = document.querySelector('.chatbot__input input');
        const chatbotSend = document.querySelector('.chatbot__input button');

        // --- Toggle Chat Window ---
        chatbotButton.addEventListener('click', () => {
            chatbotWindow.classList.toggle('show');
        });

        chatbotClose.addEventListener('click', () => {
            chatbotWindow.classList.remove('show');
        });

        // --- Send Message ---
        const sendMessage = () => {
            const messageText = chatbotInput.value.trim();
            if (messageText === '') return;

            // 1. Add user message to conversation
            const userMessage = document.createElement('div');
            userMessage.classList.add('chatbot__message', 'chatbot__message--user');
            userMessage.innerHTML = `<p>${messageText}</p>`;
            chatbotConversation.appendChild(userMessage);

            // 2. Clear input and scroll to bottom
            chatbotInput.value = '';
            chatbotConversation.scrollTop = chatbotConversation.scrollHeight;

            // 3. Get AI response
            getAiResponse(messageText);
        };

        chatbotSend.addEventListener('click', sendMessage);
        chatbotInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });

        // --- Get AI Response ---
        const getAiResponse = async (userMessage) => {
            // Show a typing indicator
            const typingIndicator = document.createElement('div');
            typingIndicator.classList.add('chatbot__message', 'chatbot__message--assistant');
            typingIndicator.innerHTML = `<p>...</p>`;
            chatbotConversation.appendChild(typingIndicator);
            chatbotConversation.scrollTop = chatbotConversation.scrollHeight;

            try {
                // This is where you would make a call to your backend
                // We will create a placeholder endpoint '/ask-ai' in app.py
                const response = await fetch('/ask-ai', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ message: userMessage }),
                });

                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }

                const data = await response.json();
                const aiMessage = data.reply;

                // Replace typing indicator with actual message
                typingIndicator.innerHTML = `<p>${aiMessage}</p>`;

            } catch (error) {
                console.error('Error fetching AI response:', error);
                typingIndicator.innerHTML = `<p>Sorry, something went wrong. Please try again.</p>`;
            }
            
            chatbotConversation.scrollTop = chatbotConversation.scrollHeight;
        };
    }
});
