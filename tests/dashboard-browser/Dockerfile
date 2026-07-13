FROM mcr.microsoft.com/playwright:v1.61.0-noble

WORKDIR /tests
RUN npm install --no-save @playwright/test@1.61.0
COPY dashboard.spec.js ./dashboard.spec.js

CMD ["npx", "playwright", "test", "dashboard.spec.js", "--workers=1", "--reporter=line"]
