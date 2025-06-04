# Rclone GUI: A User-Friendly Interface for Cloud Storage Management

<img src="https://raw.githubusercontent.com/deminimis/RcloneGUI/main/assets/Rclone%20GUI.png" alt="My Image" style="width:50%;">




## Introduction

Effortlessly manage your files across multiple cloud storage providers like pCloud, all from a modern desktop application. **Rclone GUI** brings the power of [rclone](https://rclone.org/), a command-line tool for syncing files with cloud services, into an intuitive graphical interface. Whether you're a casual user looking to back up files or a power user automating complex sync tasks, this GUI simplifies the process while retaining rclone's robust functionality.

Rclone GUI allows you to browse local and remote file systems, perform copy/sync operations, configure cloud remotes, and automate repetitive tasks via batch scripts. 

The Rclone GUI revolutionizes the user experience of managing cloud storage by allowing users to save previously synced local files and folders in "associated lists" tied to specific cloud remotes. This feature eliminates the repetitive task of manually selecting the same files or directories for each sync operation. Additionally, it allows you to easily see the remote (cloud) contents and folder structures. 


### Replacement for Proprietary Cloud Software

Proprietary cloud drivers, such as Dropbox or Google Drive, often come with bloated, proprietary, and anti-privacy drivers/software, and dependency on vendor-specific ecosystems. Rclone GUI, paired with rclone’s extensive support for over 40 cloud providers, completely bypasses these limitations. By saving sync configurations and offering a unified interface for multiple cloud services, it negates the need to install separate drivers for each provider. The GUI’s ability to automate remote setup (e.g., for pCloud) and manage encrypted configurations further enhances its independence from proprietary solutions. Users can browse, copy, or sync files across different clouds without vendor lock-in, all within a single, open-source application.



## Installation
Literally just stick the .exe in the same folder as Rclone (also open-source, download with the link above). When you open it, it automatically reads any rclone.conf file in the directory, or helps create your first remote if there is none. 

If you have Python installed, just drop the source files in the directory and run `rclone_gui.py`, not .exe needed. 

## Features

![Logo](https://github.com/deminimis/RcloneGUI/blob/main/assets/rclone2.png)
![Logo](https://github.com/deminimis/RcloneGUI/blob/main/assets/rclone3.png) 

- **Intuitive File Navigation**: Browse local and remote (cloud) directories side-by-side with double-click navigation for folders.
- **Seamless Operations**: Perform copy or sync operations between local and remote locations with customizable flags (e.g., `-P --checksum`).
- **Associated Lists**: Save frequently used local files/folders for a specific remote and sync them with one click.
- **Batch Script Generation**: Create Windows batch files for automated or scheduled sync tasks, with options for logging and password handling.
- **Automated Remote Setup**: Configure pCloud remotes with guided automation, including browser-based authentication.
- **Encrypted Config Support**: Handles password-protected rclone configurations securely.
- **Detailed Logging**: Comprehensive logs to `log.txt` and a GUI log window for real-time feedback.




### Usage
1. **Configure Remotes**: Use the "Configure (CMD)" button for manual rclone configuration or the "Auto-Setup" feature for pCloud (I will add more support later for other cloud providers later).
2. **Browse and Sync**:
   - Select a local directory and a cloud remote to view their contents.
   - Double-click folders to navigate.
   - Select files/folders and use "Copy" or "Sync" buttons to transfer data.
3. **Manage Associated Lists**: Save local paths to a remote’s associated list for quick access and batch operations.
4. **Generate Batch Files**: Create scripts for automated sync tasks, customizable with logging and password options. Then just point the Task Scheduler to that .bat file to automatically run at designated times/intervals. 

<img src="https://github.com/deminimis/RcloneGUI/blob/main/assets/rclone4.png" alt="My Image" style="width:50%;">


## Technical Details

### Architecture
The Rclone GUI is a Python application built with `tkinter` and `ttk` for the interface, leveraging rclone’s command-line capabilities. Key components include:

- **`rclone_gui.py`**: The main GUI logic, handling the primary interface, file listings, and user interactions.
- **`rclone_wrapper.py`**: Abstracts rclone command execution, handling subprocesses, environment variables, and error logging.
- **`autoconfig.py`**: Automates pCloud remote setup by scripting rclone’s interactive configuration process.
- **`graphite_theme.py`**: Defines a custom dark theme with a flat, modern aesthetic.
- **`log_utils.py`**: Manages logging to both a file (`log.txt`) and the GUI, with error handling and UTF-8 support.

### Security and Privacy
- **Encrypted Configurations**: The GUI supports rclone’s encrypted configuration files. It prompts for a password at startup if encryption is detected (`rclone_wrapper.check_if_config_encrypted`). The password is stored in memory only for the session and passed to rclone via the `RCLONE_CONFIG_PASS` environment variable.
- **Batch Script Password Handling**:
  - **Prompt Option**: Batch scripts can prompt for passwords interactively, avoiding hardcoded credentials. You will need to input the password in the command prompt each time to sync/copy to drive. 
  - **Hardcode Option**: Users can hardcode passwords in scripts (with warnings about insecurity). Scripts use `@echo off` to minimize exposure in console output.
- **No External Dependencies**: The GUI uses only standard Python libraries, reducing attack surfaces from third-party packages.
- **File Access**: Local file operations are restricted to user-selected directories via `filedialog`. Remote operations rely on rclone’s secure protocols (e.g., OAuth for pCloud).
- **Logging Privacy**: Logs avoid sensitive data like passwords. The `log_utils` module ensures UTF-8 encoding and redirects `stderr` to logs for debugging without exposing credentials.

### Technical Highlights
- **Threading for Automation**: The `autoconfig.automate_pcloud_config` function uses threads to stream rclone output and handle browser authentication, ensuring non-blocking GUI operation. A `queue.Queue` facilitates communication between the automation thread and GUI.
- **Subprocess Management**: `rclone_wrapper.run_rclone_command` supports both interactive (for config) and non-interactive (for file operations) subprocesses with `CREATE_NO_WINDOW` to minimize console popups.
- **Error Handling**: Comprehensive exception handling across modules, with fallbacks like `PrintLogger` if `log_utils` fails. Uncaught exceptions are logged to `rclone_gui_fatal_error.txt`.
- **JSON Persistence**: Associated lists are saved to `rclone_gui_associated_lists.json` with UTF-8 encoding, ensuring cross-session persistence.

### Limitations and Future Improvements
- **Single Provider for Auto-Setup**: Currently, only pCloud is supported for automated configuration. Future versions could add Dropbox, Google Drive, etc.
- **Windows-Centric**: Batch script generation and some path handling assume Windows. Cross-platform support (e.g., shell scripts for Linux/macOS) could be added.
- **Testing Coverage**: Some error paths are marked `# pragma: no cover` due to difficulty simulating (e.g., rclone executable missing). Additional integration tests could enhance reliability.
- **Sync to local**: You can currently copy and sync individua files from the remote cloud to your local, but the batch generator and .json do not yet support this.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes with clear messages (`git commit -m 'Add feature X'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request with a detailed description.

Focus areas for contributions:
- Additional cloud provider support for `autoconfig`.
- Cross-platform batch script equivalents (e.g., Bash for Linux).
- Unit tests for edge cases.



## Acknowledgments
- Built on [rclone](https://rclone.org/), a powerful open-source tool for cloud storage.
- Inspired by the need for a user-friendly interface to simplify rclone’s command-line workflows.


---

**Note**: Always secure your rclone configuration and batch scripts, especially if using encrypted configs or hardcoded passwords. Check `log.txt` for detailed logs if issues arise.
