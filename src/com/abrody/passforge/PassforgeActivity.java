package com.abrody.passforge;

import java.security.GeneralSecurityException;
import java.util.concurrent.Callable;

import com.abrody.passforge.Passforge;
import com.abrody.passforge.R;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.DialogInterface.OnCancelListener;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import android.widget.AdapterView.OnItemSelectedListener;

public class PassforgeActivity extends Activity implements OnClickListener, OnItemSelectedListener, OnCancelListener {
	
	/**
	 * Persistent data
	 */
	protected SharedPreferences settings;
	
	/**
	 * Instance of the long running task class.
	 */
	protected DeriveKeyTask mDeriveKeyTask;
	
	/**
	 * Progress dialog.
	 */
	protected ProgressDialog pd;
	
	/**
	 * Whether the generation job is running.
	 */
	protected boolean taskRunning;
	
	/**
	 * Speed in iterations per second of last computation.
	 */
	protected int iterationSpeed;
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        Button button = (Button)findViewById(R.id.ok);
        button.setOnClickListener(this);
        
        Spinner spinner = (Spinner)findViewById(R.id.iterations);
        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
        		this, R.array.iterations_array, android.R.layout.simple_spinner_item);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        spinner.setOnItemSelectedListener(this);
        
        // Set iterations to last setting or default
        int defaultPosition = getResources().getInteger(R.integer.iterations_default_position);
        settings = getPreferences(MODE_PRIVATE);
    	setIterations(settings.getInt("iterations", 10000));
    	spinner.setSelection(settings.getInt("iterations_pos", defaultPosition));
    	
    	// Load the performance metrics from last session, if any.
    	loadPerformance();
    }
    
    public void popToast(CharSequence message, boolean isLong) {
    	int length;
    	
    	if (isLong) {
    		length = Toast.LENGTH_LONG;
    	} else {
    		length = Toast.LENGTH_SHORT;
    	}
    	
    	Context context = getApplicationContext();
    	Toast toast = Toast.makeText(context, message, length);
    	toast.setGravity(Gravity.CENTER, 0, -50);
    	toast.show();
    }
    
    public void onClick(View v) {
    	generatePassword();
    }
    
    public void generatePassword() {
    	// Do nothing if we're already running.
    	if (taskRunning) {
    		return;
    	}
    	
    	// Get salt and master password from widgets.
    	EditText eSalt = (EditText)findViewById(R.id.editSalt);
    	EditText ePass = (EditText)findViewById(R.id.editMaster);
    	String pass = ePass.getText().toString();
    	String salt = eSalt.getText().toString();
    	
    	int iterations;
    	try {
    		iterations = getIterations();
    	} catch (NumberFormatException e) {
    		iterations = 1;
    	}
    	
    	Passforge p;
		try {
			p = new Passforge(pass, salt.getBytes(), iterations);
			mDeriveKeyTask = new DeriveKeyTask(p);
			mDeriveKeyTask.execute();
		} catch (GeneralSecurityException e) {
			Log.e("Passforge", "GeneralSecurityException");
			popToast("ERROR", true);
		} catch (IllegalArgumentException e) {
			popToast(e.getMessage(), true);
		}
    }
    
    @Override
    public void onCancel(DialogInterface dialog) {
    	cancelDeriveKey();
    	dialog.dismiss();
    }
    
    private void createProgressDialog(int iterations) {
    	float expectedTime = ((float) iterations / this.iterationSpeed);
    	
    	// Figure out whether seconds should be plural
    	String timeString = String.format("%.0f", expectedTime);
    	boolean plural = true;
    	if (timeString.equals("1")) {
    		plural = false; 
    	}
    	
    	pd = ProgressDialog.show(this,
    			"Generating password...",
    			String.format("Estimated time: %s second%s.\nPress back to cancel.",
    					timeString, plural ? "s" : ""),
    			true, true, this);
    }
    
    private void cancelDeriveKey() {
    	if (mDeriveKeyTask != null && mDeriveKeyTask.getStatus() == DeriveKeyTask.Status.RUNNING) {
    		mDeriveKeyTask.cancel(true);
    	}
    }
    
    private class DeriveKeyTask extends AsyncTask<Void, Void, Void> {
        private Passforge forge;
    	
        public DeriveKeyTask(Passforge forge) {
    		super();
    		this.forge = forge;
    	}
    	
    	@Override
    	protected void onPreExecute() {
    		createProgressDialog(forge.iterations);
    		taskRunning = true;
    	}
    	
    	/**
    	 * Worker thread to actually run PBKDF2 without pausing UI.
    	 */
    	@Override
    	protected Void doInBackground(Void ... unused) {
    		try {
				forge.generatePassword();
			} catch (GeneralSecurityException e) {
			}
			return null;
    	}
    	
    	/**
    	 * Update UI with results of PBKDF2 computation (runs in UI thread).
    	 */
    	@Override
    	protected void onPostExecute(Void unused) {
    		// Only save the settings if we completed the worker thread successfully.
    		Spinner spinner = (Spinner)findViewById(R.id.iterations);
    		saveIterations(spinner.getSelectedItemPosition(), forge.iterations);
    		
    		if (pd != null) {
    			pd.dismiss();
    		}
        	
    		// Save performance information.
    		savePerformance(forge.iterations, forge.getElapsedSeconds());
    		
    		// Display results.
    		showGeneratedPassword(forge.getGeneratedPassword(), forge.getElapsedSeconds());
    		taskRunning = false;
    	}
    	
    	/**
    	 * Update UI if the task was cancelled.
    	 */
    	@Override
    	protected void onCancelled() {
    		// TODO: display this with something else?
    		popToast("cancelled", false);
    		taskRunning = false;
    	}
    	
    }
    
    /*
     *  Spinner methods: onItemSelected, onNothingSelected
     */
	public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
		int[] values = getResources().getIntArray(R.array.iterations_vals_array);
		int iterations = values[pos];
		
		// Toggle the custom iterations text field as needed.
		if (iterations == getResources().getInteger(R.integer.iterations_custom_val)) {
			// Show text field and allow user to change its value.
			setCustomIterations(true);
		} else {
			// Hide text field and set its value to the spinner's value.
			setCustomIterations(false);
			
			setIterations(iterations);
		}
	}

	public void onNothingSelected(AdapterView<?> parent) {
		// do nothing.
	}
	
	private void setIterations(int iterations) {
		EditText eIter = (EditText)findViewById(R.id.editIterations);
		eIter.setText(Integer.toString(iterations));
	}
	private int getIterations() {
		EditText eIter = (EditText)findViewById(R.id.editIterations);
		return Integer.parseInt(eIter.getText().toString());
	}
	
	private void saveIterations(int pos, int iterations) {
		SharedPreferences.Editor editor = settings.edit();
		editor.putInt("iterations", iterations);
		editor.putInt("iterations_pos", pos);
		editor.commit();
	}
	
	/**
	 * Save the most recent performance to private settings.
	 * 
	 * @param iterations
	 * @param seconds
	 */
	private void savePerformance(int iterations, float seconds) {
		// Average the latest performance with all prior performance.
		int newspeed = (int) (iterations / seconds);
		this.iterationSpeed = (newspeed + iterationSpeed) / 2;
		SharedPreferences.Editor editor = settings.edit();
		editor.putInt("iteration_speed", iterationSpeed);
		editor.commit();
	}
	
	/**
	 * Load the last performance from saved settings.
	 */
	private void loadPerformance() {
		this.iterationSpeed = settings.getInt("iteration_speed", 2000);
	}
	
	private void setCustomIterations(boolean customEnabled) {
		EditText eIter = (EditText)findViewById(R.id.editIterations);
		if (customEnabled) {
			eIter.setVisibility(View.VISIBLE);
		} else {
			eIter.setVisibility(View.GONE);
		}
	}
	
	private void showGeneratedPassword(String password, float elapsedSeconds) {
		String text = password + String.format(" in %.2fs", elapsedSeconds);
		
		// TODO: save this to a UI element instead of popping up a toast.
		popToast(text, true);
	}
}

/* Helper for Passforge timing information */
class AndroidSystemClock implements Callable<Long> {
	public Long call() {
		return android.os.SystemClock.uptimeMillis();
	}
}
