
class TutorialGuide {
    constructor() {
        this.currentStep = 0;
        this.overlay = null;
        this.steps = [
            {
                element: '.nav_btn[href="/"]',
                text: 'Welcome to InI Development! Start your journey here at the home page.'
            },
            {
                element: '.nav_btn[href="/services"]',
                text: 'Check out our range of web development and maintenance services.'
            },
            {
                element: '.nav_btn[href="/portfolio"]',
                text: 'View our portfolio to see our previous work.'
            },
            {
                element: '.nav_btn[href="/contact"]',
                text: 'Get in touch with us to discuss your project.'
            },
            {
                element: '.nav_btn[href="/login"]',
                text: 'Login to access your dashboard and manage your projects.'
            }
        ];
    }

    start() {
        this.currentStep = 0;
        this.overlay = document.createElement('div');
        this.overlay.className = 'tutorial-overlay';
        document.body.appendChild(this.overlay);
        this.overlay.style.display = 'block';
        this.showStep(0);
    }

    showStep(index) {
        if (index >= this.steps.length) {
            this.end();
            return;
        }

        this.clearStep();
        const step = this.steps[index];
        const element = document.querySelector(step.element);
        
        if (!element) {
            this.showStep(index + 1);
            return;
        }

        const rect = element.getBoundingClientRect();
        
        // Create highlight
        const highlight = document.createElement('div');
        highlight.className = 'tutorial-highlight';
        highlight.style.top = `${rect.top - 4}px`;
        highlight.style.left = `${rect.left - 4}px`;
        highlight.style.width = `${rect.width + 8}px`;
        highlight.style.height = `${rect.height + 8}px`;
        document.body.appendChild(highlight);

        // Create popup
        const popup = document.createElement('div');
        popup.className = 'tutorial-step';
        popup.style.display = 'block';
        popup.innerHTML = `
            <p>${step.text}</p>
            <button onclick="tutorial.nextStep()" 
                    style="background: rebeccapurple; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-top: 10px;">
                ${index === this.steps.length - 1 ? 'Finish' : 'Next'}
            </button>
        `;

        // Position popup
        popup.style.top = `${rect.bottom + 10}px`;
        popup.style.left = `${rect.left}px`;
        document.body.appendChild(popup);

        this.currentStep = index;
    }

    nextStep() {
        this.showStep(this.currentStep + 1);
    }

    clearStep() {
        const highlights = document.querySelectorAll('.tutorial-highlight');
        const popups = document.querySelectorAll('.tutorial-step');
        highlights.forEach(h => h.remove());
        popups.forEach(p => p.remove());
    }

    end() {
        this.clearStep();
        if (this.overlay) {
            this.overlay.remove();
        }
    }
}

// Initialize the tutorial
const tutorial = new TutorialGuide();
