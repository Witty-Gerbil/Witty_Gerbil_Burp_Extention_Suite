# Contribution Guide

Thank you for considering contributing to this project! We appreciate your efforts to make this project better. Please follow the guidelines below to ensure a smooth contribution process.

## Getting Started

1. **Fork the Repository**
   - Go to the repository's GitHub page and click the "Fork" button in the top-right corner.

2. **Clone Your Fork**
   - Clone the forked repository to your local machine:
     ```bash
     git clone https://github.com/YOUR-USERNAME/REPO-NAME.git
     ```

3. **Navigate to the Project Directory**
   ```bash
   cd REPO-NAME
   ```

4. **Add the Upstream Repository**
   - Set up the original repository as a remote named `upstream`:
     ```bash
     git remote add upstream https://github.com/ORIGINAL-OWNER/REPO-NAME.git
     ```

5. **Create a New Branch**
   - Always create a new branch for your changes:
     ```bash
     git checkout -b feature/your-feature-name
     ```

## Making Changes

1. **Make Your Changes**
   - Add new features, fix bugs, or update documentation as needed.

2. **Commit Your Changes**
   - Write clear and descriptive commit messages:
     ```bash
     git add .
     git commit -m "Add feature XYZ or Fix issue #123"
     ```

3. **Push Your Changes**
   ```bash
   git push origin feature/your-feature-name
   ```

## Creating a Pull Request (PR)

1. **Open a Pull Request**
   - Go to your forked repository on GitHub.
   - Click on the "New Pull Request" button.
   - Ensure you're comparing your feature branch with the `main` branch of the original repository.

2. **Fill Out the PR Template**
   - Provide a title and a description for your PR.
   - Mention the issues it fixes (e.g., "Closes #123").

3. **Submit the PR**
   - Click "Create Pull Request."

## Keeping Your Fork Updated

1. **Fetch the Latest Changes**
   ```bash
   git fetch upstream
   ```

2. **Merge Changes into Your Branch**
   ```bash
   git checkout main
   git merge upstream/main
   ```

3. **Push to Your Fork**
   ```bash
   git push origin main
   ```

## Thank You!

Thank you for your contributions and for making this project better! 
