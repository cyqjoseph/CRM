# design/

Anything in this folder tells the build agent how this application should look. It is read on every build.

If you chose a style when this project was created, `reference.html` is that style: a page of colour swatches, type samples and components. It is a STYLE reference, not a page to copy. The agent matches its palette, typography, spacing and component shapes, never its content.

You can replace it, or add your own. Drop in your brand's own HTML reference, screenshots, a written description of your design language, or anything else that describes how things should look. The agent reads whatever is here.

If this folder holds nothing but this file, the agent chooses a sensible design itself. That is a normal outcome, not an error.

**Adding files here does not restyle an application that is already built.** A push triggers a redeploy of the existing code, not a new build. Ask for the restyle in the project's build chat and the next build will pick up whatever is in this folder.
