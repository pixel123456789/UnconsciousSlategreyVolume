
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
        highlight.style.top = `${rect.top - 5}px`;
        highlight.style.left = `${rect.left - 5}px`;
        highlight.style.width = `${rect.width + 10}px`;
        highlight.style.height = `${rect.height + 10}px`;
        
        // Create step popup
        const popup = document.createElement('div');
        popup.className = 'tutorial-step';
        popup.innerHTML = `
            <p>${step.text}</p>
            <button onclick="tutorial.showStep(${index + 1})" 
                    style="background: rebeccapurple; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                ${index === this.steps.length - 1 ? 'Finish' : 'Next'}
            </button>
        `;
        
        // Position popup
        popup.style.top = `${rect.bottom + 10}px`;
        popup.style.left = `${rect.left}px`;
        
        // Clear previous
        this.clearStep();
        
        // Add new elements
        document.body.appendChild(highlight);
        document.body.appendChild(popup);
        popup.style.display = 'block';
        
        this.currentStep = index;
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

let tutorial;
document.addEventListener('DOMContentLoaded', () => {
    tutorial = new TutorialGuide();
});
