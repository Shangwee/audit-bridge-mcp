import { addRegistryKeys } from "../tools/commands.js"; // adjust the path

//Example usage of the addRegistryKeys function
(async () => {
  try {
    const result = await addRegistryKeys("172.20.10.6", "shangwee", "P@ssw0rd");
    console.log("Execution Result:", result);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();

