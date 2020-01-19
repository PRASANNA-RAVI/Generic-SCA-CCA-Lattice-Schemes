clear; clc;

% parameters of the traces...
% Profiling the traces to find the differentiating Points of Interest between m = 0 and m = 1...

traces_ini = 50;
traces_final = 50;
traces_per_file = 50;
trace_length = 50000;
no_traces_used = 50;

first_set_start_index = 1; % start trace index used for profiling in trace set 1...
first_set_end_index = 50; % end trace index used for profiling in trace set 1...
second_set_start_index = 1; % start trace index used for profiling in trace set 1...
second_set_end_index = 50; % end trace index used for profiling in trace set 1...
fform_first = 'traces_50';
fform_second = 'traces_50';

disp('Calculating TVLA between m = 0 and m = 1...');

n = 0;
X=zeros(1,trace_length);
X2=zeros(1,trace_length);
path = sprintf('Kyber_m_0_traces_profiling/');
ext='.mat';
for i=traces_ini:traces_per_file:traces_final
    fname=[path fform_first ext];
%     disp(['Reading ' fname]);
    load(fname);
    traces=double(traces(first_set_start_index:first_set_end_index,:));
    % remove mean from each trace...
    for row_no = 1:1:size(traces,1)
        traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
    end
    X=X+sum(traces);
    X2=X2+sum(traces.^2);
    n=n+size(traces,1);
    clear traces scalars points;
end

m_X=X/n;
v_X=(X2-(X.^2/n))/(n-1);
v_Xn=v_X/n;

m_CKCP=m_X;
v_CKCP=abs(v_X);
v_CKCP_n=v_Xn;

n=0;
X=zeros(1,trace_length);
X2=zeros(1,trace_length);
path = sprintf('Kyber_m_1_traces_profiling/');
ext='.mat';
for i=traces_ini:traces_per_file:traces_final
    fname=[path fform_second ext];
%     disp(['Reading ' fname]);
    load(fname);
    traces=double(traces(second_set_start_index:second_set_end_index,:));
    % remove mean from each trace...
    for row_no = 1:1:size(traces,1)
        traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
    end
    X=X+sum(traces);
    X2=X2+sum(traces.^2);
    n=n+size(traces,1);
    clear traces scalars points;
end

m_X=X/n;
v_X=(X2-(X.^2/n))/(n-1);
v_Xn=v_X/n;

m_CKRP=m_X;
v_CKRP=abs(v_X);
v_CKRP_n=v_Xn;

tvla1= (m_CKRP-m_CKCP)./sqrt(v_CKCP/n+v_CKRP/n);

% figure;plot(tvla1,'color', [0,0,0]+0.7)
% hold on;
% plot([0,trace_length],[4.5,4.5],'k')
% plot([0,trace_length],[-4.5,-4.5],'k')
% xlabel('Time Samples')
% ylabel('TVLA Value')
% legend('TVLA-Set1-Set2','TVLA-PASS-FAIL-Threshold')

% Based on tvla value, we choose an appropriate threshold and choose those points as points of interest 
% that are above and below a certain threshold. We then construct a
% reduced trace and use the reduced trace to build a reduced template...

threshold = -7;
leaky_points_no_negative = 0;
for i = 1:1:trace_length
    if(tvla1(i) <= threshold) % Negative threshold
        leaky_points_no_negative = leaky_points_no_negative+1;
    end
end
leaky_indices_negative = zeros(1,leaky_points_no_negative);

k = 1;
for i = 1:1:trace_length
    if(tvla1(i) <= threshold)
        leaky_indices_negative(1,k) = i;
        k = k+1;
    end
end

threshold = 7;
leaky_points_no_positive = 0;
for i = 1:1:trace_length
    if(tvla1(i) >= threshold)
        leaky_points_no_positive = leaky_points_no_positive+1;
    end
end

leaky_indices_positive = zeros(1,leaky_points_no_positive);

k = 1;
for i = 1:1:trace_length
    if(tvla1(i) >= threshold) % Positive threshold
        leaky_indices_positive(1,k) = i;
        k = k+1;
    end
end

% Now calculate mean of each trace in the set and get a reduced template
% trace...

mean_trace_correct = zeros(1,leaky_points_no_negative+leaky_points_no_positive);
mean_trace_faulty = zeros(1,leaky_points_no_negative+leaky_points_no_positive);

path = sprintf('Kyber_m_0_traces_profiling/');
ext='.mat';
fname=[path fform_first ext];
% disp(['Reading ' fname]);
load(fname);
correct_traces=double(traces);
for row_no = 1:1:size(traces,1)
    correct_traces(row_no, :) = correct_traces(row_no, :) - mean(correct_traces(row_no, :));
end
                
for i = 1:1:leaky_points_no_negative
    sum_points = 0;
    for j = 1:1:no_traces_used
        sum_points = sum_points + correct_traces(j,leaky_indices_negative(i));
    end
    mean_trace_correct(i) = sum_points/no_traces_used;
end

for i = 1:1:leaky_points_no_positive
    sum_points = 0;
    for j = 1:1:no_traces_used
        sum_points = sum_points + correct_traces(j,leaky_indices_positive(i));
    end
    mean_trace_correct(i+leaky_points_no_negative) = sum_points/no_traces_used;
end

% Taking mean of PoI in trace set 2 for all traces...

path = sprintf('Kyber_m_1_traces_profiling/');    
ext='.mat';
fname=[path fform_second ext];
% disp(['Reading ' fname]);
load(fname);
faulty_traces=double(traces);
for row_no = 1:1:size(traces,1)
    faulty_traces(row_no, :) = faulty_traces(row_no, :) - mean(faulty_traces(row_no, :));
end

for i = 1:1:leaky_points_no_negative
    sum_points = 0;
    for j = 1:1:no_traces_used
        sum_points = sum_points + faulty_traces(j,leaky_indices_negative(i));
    end
    mean_trace_faulty(i) = sum_points/no_traces_used;
end

for i = 1:1:leaky_points_no_positive
    sum_points = 0;
    for j = 1:1:no_traces_used
        sum_points = sum_points + faulty_traces(j,leaky_indices_positive(i));
    end
    mean_trace_faulty(i+leaky_points_no_negative) = sum_points/no_traces_used;
end

% Figure of clustering of the two clusters...

% figure;
% hold on;
% plot(mean_trace_correct,'b');
% plot(mean_trace_faulty,'r');

% Performing the actual attack (LSQ test based on reduced templates)...

no_attack_files = 256; % Total number of coefficients...
no_attack_traces = 1280; % Five trials for each coefficient (256 * 5)
no_traces_in_file = 5;

means_attack = zeros(no_attack_files,no_traces_in_file);
means_label = zeros(no_attack_files,no_traces_in_file);

reduced_trace = zeros(1,leaky_points_no_negative+leaky_points_no_positive);

% Performing attack based on attack_threshold...

disp('Performing attack on poly 1 of secret...');

succ = 0;

for i = 1:1:no_attack_files
    path = sprintf('Kyber_attack_traces_poly_1/spot_0_0/');
    fform = 'traces_';
    ext='.mat';
    trace_no = num2str(i*5);
    fname=[path fform trace_no ext];
    load(fname);
    traces=double(traces);
    for row_no = 1:1:size(traces,1)
        traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
    end
    for k = 1:1:no_traces_in_file
        index = 1;
        current_trace = traces(k,:);
        for oo = 1:1:leaky_points_no_negative
            reduced_trace(index) = current_trace(leaky_indices_negative(oo));
            index = index+1;
        end
        for oo = 1:1:leaky_points_no_positive
            reduced_trace(index) = current_trace(leaky_indices_positive(oo));
            index = index+1;
        end
        lsq_correct = ((mean_trace_correct - reduced_trace)*transpose(mean_trace_correct - reduced_trace));
        lsq_faulty = ((mean_trace_faulty - reduced_trace)*transpose(mean_trace_faulty - reduced_trace));
        if(lsq_correct <= lsq_faulty)
            means_label(i,k) = 1;
        else
            means_label(i,k) = 0;
        end
    end
end

s_coeff = zeros(1,no_attack_files);

% Performing classification of the secret coefficient based on sequence of
% m = 0 or m = 1... This sequence uniquely identifies the secret
% coefficient...

for i = 1:1:no_attack_files
    if(means_label(i,1) == 0 && means_label(i,2) == 1 && means_label(i,3) == 0 && means_label(i,4) == 1 && means_label(i,5) == 0)
        s_coeff(1,i) = -2;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 1 && means_label(i,3) == 0 && means_label(i,4) == 1 && means_label(i,5) == 0)
        s_coeff(1,i) = -1;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 1 && means_label(i,3) == 1 && means_label(i,4) == 1 && means_label(i,5) == 0)
        s_coeff(1,i) = 0;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 1 && means_label(i,3) == 1 && means_label(i,4) == 0 && means_label(i,5) == 1)
        s_coeff(1,i) = 1;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 0 && means_label(i,3) == 1 && means_label(i,4) == 0 && means_label(i,5) == 1)
        s_coeff(1,i) = 2;
        continue;
    end
end

% Testing against actual secret values to calculate success rate...

% Attacking to recover coefficients of first polynomial of s...

disp('Performing attack on poly 2 of secret...');

s_coeffs_actual = load('kyber_s_coeffs.dat');

for i = 1:1:no_attack_files
    if(i == 1)
        if(s_coeffs_actual(1,i) == s_coeff(1,i))
            succ = succ+1;
        end
    else
        if(s_coeffs_actual(1,(256-(i-2))) == -1*(s_coeff(1,i)))
            succ = succ+1;
        end
    end
end

% Attacking to recover coefficients of second polynomial of s...

for i = 1:1:no_attack_files
    path = sprintf('Kyber_attack_traces_poly_2/spot_0_0/');
    fform = 'traces_';
    ext='.mat';
    trace_no = num2str(i*5);
    fname=[path fform trace_no ext];
    load(fname);
    traces=double(traces);
    for row_no = 1:1:size(traces,1)
        traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
    end
    for k = 1:1:no_traces_in_file
        index = 1;
        current_trace = traces(k,:);
        for oo = 1:1:leaky_points_no_negative
            reduced_trace(index) = current_trace(leaky_indices_negative(oo));
            index = index+1;
        end
        for oo = 1:1:leaky_points_no_positive
            reduced_trace(index) = current_trace(leaky_indices_positive(oo));
            index = index+1;
        end
        lsq_correct = ((mean_trace_correct - reduced_trace)*transpose(mean_trace_correct - reduced_trace));
        lsq_faulty = ((mean_trace_faulty - reduced_trace)*transpose(mean_trace_faulty - reduced_trace));
        if(lsq_correct <= lsq_faulty)
            means_label(i,k) = 1;
        else
            means_label(i,k) = 0;
        end
    end
end

s_coeff = zeros(1,no_attack_files);

for rr = 1:1:no_attack_files
    s_coeff(rr) = 3;
end

% Performing classification of the secret coefficient based on sequence of
% m = 0 or m = 1... This sequence uniquely identifies the secret
% coefficient...

for i = 1:1:no_attack_files
    if(means_label(i,1) == 0 && means_label(i,2) == 1 && means_label(i,3) == 0 && means_label(i,4) == 1 && means_label(i,5) == 0)
        s_coeff(1,i) = -2;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 1 && means_label(i,3) == 0 && means_label(i,4) == 1 && means_label(i,5) == 0)
        s_coeff(1,i) = -1;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 1 && means_label(i,3) == 1 && means_label(i,4) == 1 && means_label(i,5) == 0)
        s_coeff(1,i) = 0;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 1 && means_label(i,3) == 1 && means_label(i,4) == 0 && means_label(i,5) == 1)
        s_coeff(1,i) = 1;
        continue;
    elseif(means_label(i,1) == 1 && means_label(i,2) == 0 && means_label(i,3) == 1 && means_label(i,4) == 0 && means_label(i,5) == 1)
        s_coeff(1,i) = 2;
        continue;
    end
end

% Testing against actual secret values to calculate success rate...

s_coeffs_actual = load('kyber_s_coeffs.dat');

for i = 1:1:no_attack_files
    if(i == 1)
        if(s_coeffs_actual(2,i) == s_coeff(1,i))
            succ = succ+1;
        end
    else
        if(s_coeffs_actual(2,(256-(i-2))) == -1*(s_coeff(1,i)))
            succ = succ+1;
        end
    end
end

% Total Attack Success Rate...
succ_rate = succ/(no_attack_files*2)





