package com.southernstorm.noise.tests;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import org.junit.Assert;
import org.junit.Test;

public class UnitVectorTests {

  //private static final String testVectorsCommit = "5d0a74760320e5486ced302e36ccad91606aac43";

  @Test
  public void testBasicVector() throws Exception {

    File initialFile = new File("src/main/resources/noise-c-basic.txt");

    //try (InputStream stream = new URL( "https://raw.githubusercontent.com/rweather/noise-c/" + testVectorsCommit + "/tests/vector/noise-c-basic.txt").openStream())
    try (InputStream stream = new FileInputStream(initialFile))
    {
      VectorTests vectorTests = new VectorTests();
      vectorTests.processInputStream(stream);
      Assert.assertEquals(vectorTests.getFailed(), 0);
    }
  }
}
