//Waits for the DOM to be fully loaded 
document.addEventListener('DOMContentLoaded', () => {

    // Get the display element and button elements
    const display = document.querySelector('.text-area');

    const buttons = document.querySelectorAll('.button');

    // Loop through each button and add a click event listener
    buttons.forEach((button) => {

        button.addEventListener('click', () => {

            // Get the button text
            const buttonText = button.value;

            // Use a switch statement to handle different button texts
            switch (buttonText) {

                //Clear the display
                case 'AC':
                    display.value = '';
                    break;

                // Delete the last character in the display
                case 'DE':
                    display.value = display.value.slice(0, -1);
                    break;
                // Evaluate the expression in the display
                case '=':
                    try {
                        display.value = eval(display.value);
                    }
                    catch (error) {
                        display.value = 'Error!';
                    }
                    break;
                // Add the button text to the display
                default:

                    display.value += buttonText;
                    break;
            }
        });
    });
});