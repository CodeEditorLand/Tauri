(function() {
    addIcons();
    function addIcons() {
        if (document.readyState === "loading") return document.addEventListener("DOMContentLoaded", addIcons);
        const svg = document.body.appendChild(document.createElementNS("http://www.w3.org/2000/svg", "svg"));
        svg.innerHTML = `"<g id="icon-1"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-module)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.162 16V7.24H10.578L11.514 10.072C11.602 10.328 11.674 10.584 11.73 10.84C11.794 11.088 11.842 11.28 11.874 11.416C11.906 11.28 11.954 11.088 12.018 10.84C12.082 10.584 12.154 10.324 12.234 10.06L13.122 7.24H14.538V16H13.482V12.82C13.482 12.468 13.49 12.068 13.506 11.62C13.53 11.172 13.558 10.716 13.59 10.252C13.622 9.78 13.654 9.332 13.686 8.908C13.726 8.476 13.762 8.1 13.794 7.78L12.366 12.16H11.334L9.894 7.78C9.934 8.092 9.97 8.456 10.002 8.872C10.042 9.28 10.078 9.716 10.11 10.18C10.142 10.636 10.166 11.092 10.182 11.548C10.206 12.004 10.218 12.428 10.218 12.82V16H9.162Z" fill="var(--color-text)"></path></g><g id="icon-2"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-module)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.162 16V7.24H10.578L11.514 10.072C11.602 10.328 11.674 10.584 11.73 10.84C11.794 11.088 11.842 11.28 11.874 11.416C11.906 11.28 11.954 11.088 12.018 10.84C12.082 10.584 12.154 10.324 12.234 10.06L13.122 7.24H14.538V16H13.482V12.82C13.482 12.468 13.49 12.068 13.506 11.62C13.53 11.172 13.558 10.716 13.59 10.252C13.622 9.78 13.654 9.332 13.686 8.908C13.726 8.476 13.762 8.1 13.794 7.78L12.366 12.16H11.334L9.894 7.78C9.934 8.092 9.97 8.456 10.002 8.872C10.042 9.28 10.078 9.716 10.11 10.18C10.142 10.636 10.166 11.092 10.182 11.548C10.206 12.004 10.218 12.428 10.218 12.82V16H9.162Z" fill="var(--color-text)"></path></g><g id="icon-4"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-namespace)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.33 16V7.24H10.77L13.446 14.74C13.43 14.54 13.41 14.296 13.386 14.008C13.37 13.712 13.354 13.404 13.338 13.084C13.33 12.756 13.326 12.448 13.326 12.16V7.24H14.37V16H12.93L10.266 8.5C10.282 8.692 10.298 8.936 10.314 9.232C10.33 9.52 10.342 9.828 10.35 10.156C10.366 10.476 10.374 10.784 10.374 11.08V16H9.33Z" fill="var(--color-text)"></path></g><g id="icon-8"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-enum)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.45 16V7.24H14.49V8.224H10.518V10.936H14.07V11.908H10.518V15.016H14.49V16H9.45Z" fill="var(--color-text)"></path></g><g id="icon-16"><rect fill="var(--color-icon-background)" stroke="#FF984D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M9.354 16V7.24H12.174C12.99 7.24 13.638 7.476 14.118 7.948C14.606 8.412 14.85 9.036 14.85 9.82C14.85 10.604 14.606 11.232 14.118 11.704C13.638 12.168 12.99 12.4 12.174 12.4H10.434V16H9.354ZM10.434 11.428H12.174C12.646 11.428 13.022 11.284 13.302 10.996C13.59 10.7 13.734 10.308 13.734 9.82C13.734 9.324 13.59 8.932 13.302 8.644C13.022 8.356 12.646 8.212 12.174 8.212H10.434V11.428Z" fill="var(--color-text)"></path></g><g id="icon-32"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-variable)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M11.106 16L8.85 7.24H9.966L11.454 13.192C11.558 13.608 11.646 13.996 11.718 14.356C11.79 14.708 11.842 14.976 11.874 15.16C11.906 14.976 11.954 14.708 12.018 14.356C12.09 13.996 12.178 13.608 12.282 13.192L13.758 7.24H14.85L12.582 16H11.106Z" fill="var(--color-text)"></path></g><g id="icon-64"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-function)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.39 16V7.24H14.55V8.224H10.446V11.128H14.238V12.112H10.47V16H9.39Z" fill="var(--color-text)"></path></g><g id="icon-128"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-class)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M11.898 16.1201C11.098 16.1201 10.466 15.8961 10.002 15.4481C9.53803 15.0001 9.30603 14.3841 9.30603 13.6001V9.64012C9.30603 8.85612 9.53803 8.24012 10.002 7.79212C10.466 7.34412 11.098 7.12012 11.898 7.12012C12.682 7.12012 13.306 7.34812 13.77 7.80412C14.234 8.25212 14.466 8.86412 14.466 9.64012H13.386C13.386 9.14412 13.254 8.76412 12.99 8.50012C12.734 8.22812 12.37 8.09212 11.898 8.09212C11.426 8.09212 11.054 8.22412 10.782 8.48812C10.518 8.75212 10.386 9.13212 10.386 9.62812V13.6001C10.386 14.0961 10.518 14.4801 10.782 14.7521C11.054 15.0161 11.426 15.1481 11.898 15.1481C12.37 15.1481 12.734 15.0161 12.99 14.7521C13.254 14.4801 13.386 14.0961 13.386 13.6001H14.466C14.466 14.3761 14.234 14.9921 13.77 15.4481C13.306 15.8961 12.682 16.1201 11.898 16.1201Z" fill="var(--color-text)"></path></g><g id="icon-256"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-interface)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.51 16V15.016H11.298V8.224H9.51V7.24H14.19V8.224H12.402V15.016H14.19V16H9.51Z" fill="var(--color-text)"></path></g><g id="icon-512"><rect fill="var(--color-icon-background)" stroke="#4D7FFF" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M11.898 16.1201C11.098 16.1201 10.466 15.8961 10.002 15.4481C9.53803 15.0001 9.30603 14.3841 9.30603 13.6001V9.64012C9.30603 8.85612 9.53803 8.24012 10.002 7.79212C10.466 7.34412 11.098 7.12012 11.898 7.12012C12.682 7.12012 13.306 7.34812 13.77 7.80412C14.234 8.25212 14.466 8.86412 14.466 9.64012H13.386C13.386 9.14412 13.254 8.76412 12.99 8.50012C12.734 8.22812 12.37 8.09212 11.898 8.09212C11.426 8.09212 11.054 8.22412 10.782 8.48812C10.518 8.75212 10.386 9.13212 10.386 9.62812V13.6001C10.386 14.0961 10.518 14.4801 10.782 14.7521C11.054 15.0161 11.426 15.1481 11.898 15.1481C12.37 15.1481 12.734 15.0161 12.99 14.7521C13.254 14.4801 13.386 14.0961 13.386 13.6001H14.466C14.466 14.3761 14.234 14.9921 13.77 15.4481C13.306 15.8961 12.682 16.1201 11.898 16.1201Z" fill="var(--color-text)"></path></g><g id="icon-1024"><rect fill="var(--color-icon-background)" stroke="#FF984D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M9.354 16V7.24H12.174C12.99 7.24 13.638 7.476 14.118 7.948C14.606 8.412 14.85 9.036 14.85 9.82C14.85 10.604 14.606 11.232 14.118 11.704C13.638 12.168 12.99 12.4 12.174 12.4H10.434V16H9.354ZM10.434 11.428H12.174C12.646 11.428 13.022 11.284 13.302 10.996C13.59 10.7 13.734 10.308 13.734 9.82C13.734 9.324 13.59 8.932 13.302 8.644C13.022 8.356 12.646 8.212 12.174 8.212H10.434V11.428Z" fill="var(--color-text)"></path></g><g id="icon-2048"><rect fill="var(--color-icon-background)" stroke="#FF4DB8" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M9.162 16V7.24H10.578L11.514 10.072C11.602 10.328 11.674 10.584 11.73 10.84C11.794 11.088 11.842 11.28 11.874 11.416C11.906 11.28 11.954 11.088 12.018 10.84C12.082 10.584 12.154 10.324 12.234 10.06L13.122 7.24H14.538V16H13.482V12.82C13.482 12.468 13.49 12.068 13.506 11.62C13.53 11.172 13.558 10.716 13.59 10.252C13.622 9.78 13.654 9.332 13.686 8.908C13.726 8.476 13.762 8.1 13.794 7.78L12.366 12.16H11.334L9.894 7.78C9.934 8.092 9.97 8.456 10.002 8.872C10.042 9.28 10.078 9.716 10.11 10.18C10.142 10.636 10.166 11.092 10.182 11.548C10.206 12.004 10.218 12.428 10.218 12.82V16H9.162Z" fill="var(--color-text)"></path></g><g id="icon-4096"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-function)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M9.39 16V7.24H14.55V8.224H10.446V11.128H14.238V12.112H10.47V16H9.39Z" fill="var(--color-text)"></path></g><g id="icon-8192"><rect fill="var(--color-icon-background)" stroke="#FF984D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M9.354 16V7.24H12.174C12.99 7.24 13.638 7.476 14.118 7.948C14.606 8.412 14.85 9.036 14.85 9.82C14.85 10.604 14.606 11.232 14.118 11.704C13.638 12.168 12.99 12.4 12.174 12.4H10.434V16H9.354ZM10.434 11.428H12.174C12.646 11.428 13.022 11.284 13.302 10.996C13.59 10.7 13.734 10.308 13.734 9.82C13.734 9.324 13.59 8.932 13.302 8.644C13.022 8.356 12.646 8.212 12.174 8.212H10.434V11.428Z" fill="var(--color-text)"></path></g><g id="icon-16384"><rect fill="var(--color-icon-background)" stroke="#4D7FFF" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M11.898 16.1201C11.098 16.1201 10.466 15.8961 10.002 15.4481C9.53803 15.0001 9.30603 14.3841 9.30603 13.6001V9.64012C9.30603 8.85612 9.53803 8.24012 10.002 7.79212C10.466 7.34412 11.098 7.12012 11.898 7.12012C12.682 7.12012 13.306 7.34812 13.77 7.80412C14.234 8.25212 14.466 8.86412 14.466 9.64012H13.386C13.386 9.14412 13.254 8.76412 12.99 8.50012C12.734 8.22812 12.37 8.09212 11.898 8.09212C11.426 8.09212 11.054 8.22412 10.782 8.48812C10.518 8.75212 10.386 9.13212 10.386 9.62812V13.6001C10.386 14.0961 10.518 14.4801 10.782 14.7521C11.054 15.0161 11.426 15.1481 11.898 15.1481C12.37 15.1481 12.734 15.0161 12.99 14.7521C13.254 14.4801 13.386 14.0961 13.386 13.6001H14.466C14.466 14.3761 14.234 14.9921 13.77 15.4481C13.306 15.8961 12.682 16.1201 11.898 16.1201Z" fill="var(--color-text)"></path></g><g id="icon-32768"><rect fill="var(--color-icon-background)" stroke="#FF984D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M9.354 16V7.24H12.174C12.99 7.24 13.638 7.476 14.118 7.948C14.606 8.412 14.85 9.036 14.85 9.82C14.85 10.604 14.606 11.232 14.118 11.704C13.638 12.168 12.99 12.4 12.174 12.4H10.434V16H9.354ZM10.434 11.428H12.174C12.646 11.428 13.022 11.284 13.302 10.996C13.59 10.7 13.734 10.308 13.734 9.82C13.734 9.324 13.59 8.932 13.302 8.644C13.022 8.356 12.646 8.212 12.174 8.212H10.434V11.428Z" fill="var(--color-text)"></path></g><g id="icon-65536"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-type-alias)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M11.31 16V8.224H8.91V7.24H14.79V8.224H12.39V16H11.31Z" fill="var(--color-text)"></path></g><g id="icon-131072"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-type-alias)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M11.31 16V8.224H8.91V7.24H14.79V8.224H12.39V16H11.31Z" fill="var(--color-text)"></path></g><g id="icon-262144"><rect fill="var(--color-icon-background)" stroke="#FF4D4D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M8.85 16L11.13 7.24H12.582L14.85 16H13.758L13.182 13.672H10.53L9.954 16H8.85ZM10.746 12.76H12.954L12.282 10.06C12.154 9.548 12.054 9.12 11.982 8.776C11.91 8.432 11.866 8.208 11.85 8.104C11.834 8.208 11.79 8.432 11.718 8.776C11.646 9.12 11.546 9.544 11.418 10.048L10.746 12.76Z" fill="var(--color-text)"></path></g><g id="icon-524288"><rect fill="var(--color-icon-background)" stroke="#FF4D4D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M8.85 16L11.13 7.24H12.582L14.85 16H13.758L13.182 13.672H10.53L9.954 16H8.85ZM10.746 12.76H12.954L12.282 10.06C12.154 9.548 12.054 9.12 11.982 8.776C11.91 8.432 11.866 8.208 11.85 8.104C11.834 8.208 11.79 8.432 11.718 8.776C11.646 9.12 11.546 9.544 11.418 10.048L10.746 12.76Z" fill="var(--color-text)"></path></g><g id="icon-1048576"><rect fill="var(--color-icon-background)" stroke="#FF4D4D" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M8.85 16L11.13 7.24H12.582L14.85 16H13.758L13.182 13.672H10.53L9.954 16H8.85ZM10.746 12.76H12.954L12.282 10.06C12.154 9.548 12.054 9.12 11.982 8.776C11.91 8.432 11.866 8.208 11.85 8.104C11.834 8.208 11.79 8.432 11.718 8.776C11.646 9.12 11.546 9.544 11.418 10.048L10.746 12.76Z" fill="var(--color-text)"></path></g><g id="icon-2097152"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-type-alias)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><path d="M11.31 16V8.224H8.91V7.24H14.79V8.224H12.39V16H11.31Z" fill="var(--color-text)"></path></g><g id="icon-4194304"><rect fill="var(--color-icon-background)" stroke="#FF4D82" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="12"></rect><path d="M10.354 17V8.24H13.066C13.586 8.24 14.042 8.348 14.434 8.564C14.826 8.772 15.13 9.064 15.346 9.44C15.562 9.816 15.67 10.256 15.67 10.76C15.67 11.352 15.514 11.86 15.202 12.284C14.898 12.708 14.482 13 13.954 13.16L15.79 17H14.518L12.838 13.28H11.434V17H10.354ZM11.434 12.308H13.066C13.514 12.308 13.874 12.168 14.146 11.888C14.418 11.6 14.554 11.224 14.554 10.76C14.554 10.288 14.418 9.912 14.146 9.632C13.874 9.352 13.514 9.212 13.066 9.212H11.434V12.308Z" fill="var(--color-text)"></path></g><g id="icon-8388608"><rect fill="var(--color-icon-background)" stroke="var(--color-document)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><g stroke="var(--color-text)" fill="var(--color-icon-background)"><polygon points="6,5 6,19 18,19, 18,9 15,5"></polygon><line x1="9" y1="9" x2="14" y2="9"></line><line x1="9" y1="12" x2="15" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></g></g><g id="icon-chevronDown"><path d="M4.93896 8.531L12 15.591L19.061 8.531L16.939 6.409L12 11.349L7.06098 6.409L4.93896 8.531Z" fill="var(--color-text)"></path></g><g id="icon-chevronSmall"><path d="M1.5 5.50969L8 11.6609L14.5 5.50969L12.5466 3.66086L8 7.96494L3.45341 3.66086L1.5 5.50969Z" fill="var(--color-text)"></path></g><g id="icon-checkbox"><rect class="tsd-checkbox-background" width="30" height="30" x="1" y="1" rx="6" fill="none"></rect><path class="tsd-checkbox-checkmark" d="M8.35422 16.8214L13.2143 21.75L24.6458 10.25" stroke="none" stroke-width="3.5" stroke-linejoin="round" fill="none"></path></g><g id="icon-menu"><rect x="1" y="3" width="14" height="2" fill="var(--color-text)"></rect><rect x="1" y="7" width="14" height="2" fill="var(--color-text)"></rect><rect x="1" y="11" width="14" height="2" fill="var(--color-text)"></rect></g><g id="icon-search"><path d="M15.7824 13.833L12.6666 10.7177C12.5259 10.5771 12.3353 10.499 12.1353 10.499H11.6259C12.4884 9.39596 13.001 8.00859 13.001 6.49937C13.001 2.90909 10.0914 0 6.50048 0C2.90959 0 0 2.90909 0 6.49937C0 10.0896 2.90959 12.9987 6.50048 12.9987C8.00996 12.9987 9.39756 12.4863 10.5008 11.6239V12.1332C10.5008 12.3332 10.5789 12.5238 10.7195 12.6644L13.8354 15.7797C14.1292 16.0734 14.6042 16.0734 14.8948 15.7797L15.7793 14.8954C16.0731 14.6017 16.0731 14.1267 15.7824 13.833ZM6.50048 10.499C4.29094 10.499 2.50018 8.71165 2.50018 6.49937C2.50018 4.29021 4.28781 2.49976 6.50048 2.49976C8.71001 2.49976 10.5008 4.28708 10.5008 6.49937C10.5008 8.70852 8.71314 10.499 6.50048 10.499Z" fill="var(--color-text)"></path></g><g id="icon-anchor"><g stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M10 14a3.5 3.5 0 0 0 5 0l4 -4a3.5 3.5 0 0 0 -5 -5l-.5 .5"></path><path d="M14 10a3.5 3.5 0 0 0 -5 0l-4 4a3.5 3.5 0 0 0 5 5l.5 -.5"></path></g></g>"`;
        svg.style.display = "none";
        if (location.protocol === "file:") updateUseElements();
    }

    function updateUseElements() {
        document.querySelectorAll("use").forEach(el => {
            if (el.getAttribute("href").includes("#icon-")) {
                el.setAttribute("href", el.getAttribute("href").replace(/.*#/, "#"));
            }
        });
    }
})()