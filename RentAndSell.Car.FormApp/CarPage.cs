using RentAndSell.Car.FormApp.Commons.Enums;
using RentAndSell.Car.FormApp.Models;
using System.Net.Http.Json;

namespace RentAndSell.Car.FormApp
{
	public partial class CarPage : Form
	{
		private HttpClient _httpClient;
		private const string _endPoint = "Cars";

		public CarPage()
		{
			InitializeComponent();
			_httpClient = new HttpClient();
			_httpClient.BaseAddress = new Uri("https://localhost:7247/api/");
			_httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Authorization", Program.BasicAuth);

		}

		private void Form1_Load(object sender, EventArgs e)
		{
			cBoxYakitTuru.DataSource = Enum.GetValues(typeof(YakitTuru));
			cBoxMotorTipi.DataSource = Enum.GetValues(typeof(MotorTipi));
			cBoxSanzimanTipi.DataSource = Enum.GetValues(typeof(SanzimanTipi));

			nbrUpDownYil.Maximum = DateTime.Now.Year;
			//nbrUpDownYil.Minimum = DateTime.Now.Year - 50; // son 50 y�ll�k i� 

			//MessageBox.Show(cBoxYakitTuru.SelectedValue.ToString());
			//MessageBox.Show(cBoxMotorTipi.SelectedValue.ToString());
			//MessageBox.Show(cBoxSanzimanTipi.SelectedValue.ToString());

			//MessageBox.Show("" + (int)cBoxYakitTuru.SelectedValue);
			//MessageBox.Show("" + (int)cBoxMotorTipi.SelectedValue);
			//MessageBox.Show("" + (int)cBoxSanzimanTipi.SelectedValue);

			for (short i = 1940; i <= DateTime.Now.Year; i++)
				cBoxYil.Items.Add(i);

			cBoxYil.SelectedIndex = 0;


			ReloadedDataGridView();

		}

		private void btnSave_Click(object sender, EventArgs e)
		{
			ArabaViewModel model = new ArabaViewModel();
			model.Marka = txtMarka.Text;
			model.Model = txtModel.Text;
			model.Yili = (short)cBoxYil.SelectedItem;
			model.YakitTuru = (YakitTuru)cBoxYakitTuru.SelectedItem;
			model.MotorTipi = (MotorTipi)cBoxMotorTipi.SelectedItem;
			model.SanzimanTipi = (SanzimanTipi)cBoxSanzimanTipi.SelectedItem;

			HttpResponseMessage responseMessage = _httpClient.PostAsJsonAsync(_endPoint, model).Result;

			if (responseMessage.IsSuccessStatusCode)
			{
				MessageBox.Show("Kay�t ba�ar�l�d�r. Yan�t: " + responseMessage.Content.ReadAsStringAsync().Result);

				ReloadedDataGridView();
			}

			else
				MessageBox.Show("Kay�t yap�lamad�");

		}

		private void ReloadedDataGridView()
		{
			List<ArabaViewModel> arabaViewModels = _httpClient.GetFromJsonAsync<List<ArabaViewModel>>(_endPoint).Result;

			dgvArabaList.DataSource = arabaViewModels;

			ClearFrom();
		}

		private void dgvArabaList_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
		{
			//List<ArabaViewModel> arabaViewModels = _httpClient.GetFromJsonAsync<List<ArabaViewModel>>(_endPoint).Result;

			ArabaViewModel selectedAraba = (ArabaViewModel)dgvArabaList.SelectedRows[0].DataBoundItem;

			txtId.Text = selectedAraba.Id.ToString();
			txtMarka.Text = selectedAraba.Marka;
			txtModel.Text = selectedAraba.Model;

			cBoxYil.SelectedItem = selectedAraba.Yili;
			cBoxYakitTuru.SelectedItem = selectedAraba.YakitTuru;
			cBoxMotorTipi.SelectedItem = selectedAraba.MotorTipi;
			cBoxSanzimanTipi.SelectedItem = selectedAraba.SanzimanTipi;


		}

		private void btnGuncelle_Click(object sender, EventArgs e)
		{
			ArabaViewModel model = new ArabaViewModel();
			model.Marka = txtMarka.Text;
			model.Model = txtModel.Text;
			model.Yili = (short)cBoxYil.SelectedItem;
			model.YakitTuru = (YakitTuru)cBoxYakitTuru.SelectedItem;
			model.MotorTipi = (MotorTipi)cBoxMotorTipi.SelectedItem;
			model.SanzimanTipi = (SanzimanTipi)cBoxSanzimanTipi.SelectedItem;

			string id = txtId.Text;

			// https://localhost:7247/api/Cars/3 => put

			HttpResponseMessage responseMessage = _httpClient.PutAsJsonAsync(_endPoint + $"/{id}", model).Result;

			if (responseMessage.IsSuccessStatusCode)
			{
				MessageBox.Show("G�ncelleme ba�ar�l�d�r. Yan�t: " + responseMessage.Content.ReadAsStringAsync().Result);

				ReloadedDataGridView();
			}

			else
				MessageBox.Show("G�ncelleme yap�lamad�");
		}

		private void btnSil_Click(object sender, EventArgs e)
		{
			string id = txtId.Text;

			// https://localhost:7247/api/Cars/3 => delete

			HttpResponseMessage responseMessage = _httpClient.DeleteAsync(_endPoint + $"/{id}").Result;

			if (responseMessage.IsSuccessStatusCode)
			{
				MessageBox.Show("Silme ba�ar�l�d�r. Yan�t: " + responseMessage.Content.ReadAsStringAsync().Result);

				ReloadedDataGridView();
			}

			else
				MessageBox.Show("Silme yap�lamad�");
		}

		private void ClearFrom()
		{
			txtId.Clear();
			txtMarka.Clear();
			txtModel.Clear();
			cBoxYil.SelectedIndex = 0;
			cBoxYakitTuru.SelectedIndex = 0;
			cBoxMotorTipi.SelectedIndex = 0;
			cBoxSanzimanTipi.SelectedIndex = 0;
		}

		private void btnRead_Click(object sender, EventArgs e)
		{
			//buras� db den orjinal kayd� okumak i�in 

			string carID = txtCarId.Text;

			// https://localhost:7247/api/Cars/3 => delete

			ArabaViewModel model = _httpClient.GetFromJsonAsync<ArabaViewModel>(_endPoint + $"/{carID}").Result;

			if (model != null)
			{
				string metin = $@"
							Marka : {model.Marka}
							Model : {model.Model}
							Y�l� : {model.Yili}
							Yak�t T�r� : {model.YakitTuru}
							Motor Tipi : {model.MotorTipi}
							�anz�man Tipi : {model.SanzimanTipi}
							";

				MessageBox.Show(metin);
			}

			else
				MessageBox.Show("Silme yap�lamad�");
		}
	}
}
