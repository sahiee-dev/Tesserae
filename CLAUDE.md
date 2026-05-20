## Git Operations
- NEVER commit generated assets (images, figures, build artifacts) unless explicitly asked
- Before switching branches or stashing, ALWAYS confirm with the user if there are uncommitted changes - explain what will happen to their local work
- When user wants to push local content, prefer committing on current branch first before any branch operations

## External CLI Tools
- Before running `gh`, `git push`, or other auth-requiring CLIs, check auth status first (e.g., `gh auth status`) and prompt user to authenticate if needed rather than failing mid-task

## Figure Generation
- When regenerating paper figures, verify text isn't clipped and all referenced classes/elements are included before declaring done
- Default to checking layout spacing (titles, labels, legends) in a first pass
