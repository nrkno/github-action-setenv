module.exports = {
  branches: ["main"],
  plugins: [
    "@semantic-release/commit-analyzer",
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "conventionalcommits",
        writerOpts: {
          commitPartial: `* {{header}}
{{#if body}}
  _{{{body}}}_
{{/if}}
`,
        },
      },
    ],
    ["@semantic-release/github"],
    ["semantic-release-tags"],
  ],
};
