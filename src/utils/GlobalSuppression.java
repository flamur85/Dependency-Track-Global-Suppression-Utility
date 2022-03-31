package utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * @author Tony Bomova (flamur85@gmail.com)
 */
public class GlobalSuppression {
	private static String DEPENDENCY_TRACK_BASE_URL = ""; // example: https://dependencytrack.internal.io/api/v1/
	private static String DEPENDENCY_TRACK_API_KEY = "";
	private static String PURL = "";
	private static String VULNERABILITY_UUID = "";
	private static String SUPPRESSION_STATUS = ""; // example: true (suppress) or false (unsuppress) - lower case only

	public static void main(String[] args) throws IOException {
		HashMap<String, String> projectComponent = new HashMap<String, String>();
		List<String> listOfProjectIds = new ArrayList<>();
		String projectUUID = null;

		System.out.println("**********************************************************************");
		System.out.println("Dependency Track Global Suppression Utility");
		System.out.println("**********************************************************************\n");
		System.out.println("Scanning each project for " + PURL + ". This may take a while... \n");

		/* Go through each project at one time and check if it has a specific PURL */
		HttpURLConnection getProjectAPI = getProjectAPI(DEPENDENCY_TRACK_API_KEY);
		try {
			JSONArray projectsArray = new JSONArray(getResponse(getProjectAPI));
			for (int i = 0; i < projectsArray.length(); i++) {
				JSONObject projectObject = projectsArray.getJSONObject(i);
				projectUUID = projectObject.getString("uuid");

				HttpURLConnection getComponentsApi = getComponentsAPI(DEPENDENCY_TRACK_API_KEY, projectUUID);
				JSONArray componentsArray = new JSONArray(getResponse(getComponentsApi));

				/* If the project has the specified PURL, add both to a hash map for processing.*/
				for (int x = 0; x < componentsArray.length(); x++) {
					JSONObject componentsObject = componentsArray.getJSONObject(x);
					if (componentsObject.toString().contains(PURL)) {
						listOfProjectIds.add(projectObject.getString("name") + "\n");
						String componentUUID = componentsObject.get("uuid").toString();
						projectComponent.put(projectUUID, componentUUID);
						break;
					}
				}
			}
		} catch (JSONException e) {
			e.printStackTrace();
		}
		System.out.println("Scanning complete!\n");
		System.out.println("**********************************************************************");

		/* Print affected Project/Component UUID's */
		System.out.println("\nList of all project and component UUID's that are going to be updated.");
		for (String i : projectComponent.keySet()) {
			System.out.println("key: " + i + " value: " + projectComponent.get(i));
		}

		/* Print Component Id */
		System.out.println("\nTargeted Component Package URL: \n" + PURL);

		/* Print Vulnerability Id */
		HttpURLConnection getVulnerabilityApi = getVulnerabilityAPI(DEPENDENCY_TRACK_API_KEY, VULNERABILITY_UUID);
		try {
			JSONObject object = new JSONObject(getResponse(getVulnerabilityApi));
			String vulnId = object.get("vulnId").toString();
			System.out.println("\nTargeted Vulnerability: \n" + vulnId + " UUID: " + VULNERABILITY_UUID + "\n");
		} catch (Exception e) {
			e.printStackTrace();
		}

		/* Print affected Projects */
		System.out.println("Targeted Projects: ");
		System.out.println(listOfProjectIds);

		/* Use Analysis API to update the components */
		System.out.println("\n**********************************************************************");
		System.out.println("\nUpdates in progress. This should be quick... \n");

		for (String map : projectComponent.keySet()) {
			HttpURLConnection putAnalysisAPI = putAnalysisAPI(DEPENDENCY_TRACK_API_KEY);
			globallySuppressVulnerability(putAnalysisAPI, map, projectComponent.get(map), VULNERABILITY_UUID, SUPPRESSION_STATUS);

			String response = getResponse(putAnalysisAPI);
			if (response.contains("error")) {
				System.out.println("Something went wrong: " + response);
			}
		}

		System.out.println("**********************************************************************");
		System.out.println("Task Complete!");
		System.out.println("**********************************************************************");
	}

	private static HttpURLConnection getVulnerabilityAPI(String apiKey, String vulnId) throws MalformedURLException, IOException, ProtocolException {
		URL url = new URL(DEPENDENCY_TRACK_BASE_URL + "vulnerability/" + vulnId);
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("GET");
		httpConn.setRequestProperty("Accept", "application/json");
		httpConn.setRequestProperty("X-Api-Key", apiKey);
		return httpConn;
	}

	private static HttpURLConnection getComponentsAPI(String apiKey, String projectId) throws MalformedURLException, IOException, ProtocolException {
		URL url = new URL(DEPENDENCY_TRACK_BASE_URL + "component/project/" + projectId + "?page=1&limit=3000");
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("GET");
		httpConn.setRequestProperty("Accept", "application/json");
		httpConn.setRequestProperty("X-Api-Key", apiKey);
		return httpConn;
	}

	private static void globallySuppressVulnerability(HttpURLConnection putAnalysisAPI, String projectId, String componentId, String vulnerabilityId, String suppressionStatus) throws IOException {
		String analysisState = "FALSE_POSITIVE"; // This can be changed
		if (suppressionStatus.contains("false")) {
			analysisState = "NOT_SET";
		}
		
		OutputStreamWriter writer = new OutputStreamWriter(putAnalysisAPI.getOutputStream());
		writer.write(
				"{" + "\"project\": \"" + projectId + "\", " 
					+ "\"component\": \"" + componentId + "\", "
					+ "\"vulnerability\": \"" + vulnerabilityId + "\", " 
					+ "\"analysisState\": \"" + analysisState + "\", "
					+ "\"comment\": \"Change was made by an API User.\", " // This can be changed
					+ "\"suppressed\":" + suppressionStatus + "" + "\n }");
		writer.flush();
		writer.close();
		putAnalysisAPI.getOutputStream().close();
	}

	private static HttpURLConnection putAnalysisAPI(String apiKey) throws IOException {
		URL url = new URL(DEPENDENCY_TRACK_BASE_URL + "analysis");
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("PUT");
		httpConn.setRequestProperty("Content-Type", "application/json");
		httpConn.setRequestProperty("Accept", "application/json");
		httpConn.setRequestProperty("X-Api-Key", apiKey);
		httpConn.setDoOutput(true);
		return httpConn;
	}

	private static HttpURLConnection getProjectAPI(String apiKey) throws MalformedURLException, IOException, ProtocolException {
		URL url = new URL(DEPENDENCY_TRACK_BASE_URL + "project?page=1&limit=3000");
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("GET");
		httpConn.setRequestProperty("Accept", "application/json");
		httpConn.setRequestProperty("X-Api-Key", apiKey);
		return httpConn;
	}

	private static String getResponse(HttpURLConnection httpConn) throws IOException {
		InputStream responseStream = httpConn.getResponseCode() / 100 == 2 ? httpConn.getInputStream() : httpConn.getErrorStream();
		@SuppressWarnings("resource")
		Scanner s = new Scanner(responseStream).useDelimiter("\\A");
		String response = s.hasNext() ? s.next() : "";
		return response;
	}

	@SuppressWarnings("unused")
	private static HttpURLConnection getComponentAPI(String apiKey, String componentId) throws MalformedURLException, IOException, ProtocolException {
		URL url = new URL(DEPENDENCY_TRACK_BASE_URL + "component/" + componentId);
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("GET");
		httpConn.setRequestProperty("Accept", "application/json");
		httpConn.setRequestProperty("X-Api-Key", apiKey);
		return httpConn;
	}
}
