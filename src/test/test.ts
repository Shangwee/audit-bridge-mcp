import { 
  addRegistryKeys,
  runRemoteAuditSetup
} from "../tools/commands.js"; // adjust the path

//Example usage to test function from commands.js
(async () => {
  try {
    const result = await runRemoteAuditSetup("172.20.10.6", "shangwee", "P@ssw0rd");
    // const result = await addRegistryKeys("10.130.5.6", "shangwee", "P@ssw0rd");
    console.log("Execution Result:", result);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();

