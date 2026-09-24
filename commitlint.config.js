// commitlint.config.js
// À placer à la racine du repo (même config pour les 6 repos ESP-ODIN)
// Format attendu : type(scope): description
// Exemples : feat(auth): ajout du login OAuth
//            fix: correction du parsing du manifeste
//            chore(infra): setup commitlint

module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      ["feat", "fix", "chore", "refactor", "docs", "test", "ci", "build", "perf"],
    ],
    "scope-empty": [0], // le scope est autorisé mais pas obligatoire (repo = service déjà)
    "subject-case": [0], // le français est toléré dans les descriptions
    "header-max-length": [2, "always", 100],
  },
};
